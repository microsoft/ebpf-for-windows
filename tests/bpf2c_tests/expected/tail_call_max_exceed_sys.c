// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from tail_call_max_exceed.o

#define NO_CRT
#include "bpf2c.h"

#include <guiddef.h>
#include <wdm.h>
#include <wsk.h>

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
RTL_QUERY_REGISTRY_ROUTINE static _bpf2c_query_registry_routine;

#define metadata_table tail_call_max_exceed##_metadata_table

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
         1,                       // Current Version.
         80,                      // Struct size up to the last field.
         80,                      // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_PROG_ARRAY, // Type of map.
         4,                       // Size in bytes of a map key.
         4,                       // Size in bytes of a map value.
         35,                      // Maximum number of entries allowed in the map.
         0,                       // Inner map index.
         LIBBPF_PIN_NONE,         // Pinning type for the map.
         21,                      // Identifier for a map template.
         0,                       // The id of the inner map template.
     },
     "sample_tail_call_map"},
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

static helper_function_entry_t sample_test_callee0_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     14,
     "helper_id_14",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
};

static GUID sample_test_callee0_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sample_test_callee0_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sample_test_callee0_maps[] = {
    0,
};

#pragma code_seg(push, "sampl~36")
static uint64_t
sample_test_callee0(void* context, const program_runtime_context_t* runtime_context)
#line 85 "sample/tail_call_max_exceed.c"
{
#line 85 "sample/tail_call_max_exceed.c"
    // Prologue.
#line 85 "sample/tail_call_max_exceed.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 85 "sample/tail_call_max_exceed.c"
    register uint64_t r0 = 0;
#line 85 "sample/tail_call_max_exceed.c"
    register uint64_t r1 = 0;
#line 85 "sample/tail_call_max_exceed.c"
    register uint64_t r2 = 0;
#line 85 "sample/tail_call_max_exceed.c"
    register uint64_t r3 = 0;
#line 85 "sample/tail_call_max_exceed.c"
    register uint64_t r4 = 0;
#line 85 "sample/tail_call_max_exceed.c"
    register uint64_t r5 = 0;
#line 85 "sample/tail_call_max_exceed.c"
    register uint64_t r6 = 0;
#line 85 "sample/tail_call_max_exceed.c"
    register uint64_t r7 = 0;
#line 85 "sample/tail_call_max_exceed.c"
    register uint64_t r10 = 0;

#line 85 "sample/tail_call_max_exceed.c"
    r1 = (uintptr_t)context;
#line 85 "sample/tail_call_max_exceed.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 85 "sample/tail_call_max_exceed.c"
    r6 = r1;
#line 85 "sample/tail_call_max_exceed.c"
    r7 = IMMEDIATE(10);
#line 85 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-4));
#line 85 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1566844192);
#line 85 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-8));
#line 85 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)4404574498340937772;
#line 85 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
#line 85 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)6729544563593082971;
#line 85 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 85 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2339731488442490988;
#line 85 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 85 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099572;
#line 85 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 85 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2334956330884555075;
#line 85 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 85 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 85 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 85 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(46);
#line 85 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(0);
#line 85 "sample/tail_call_max_exceed.c"
    r4 = IMMEDIATE(1);
#line 85 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 85 "sample/tail_call_max_exceed.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[0].address);
#line 85 "sample/tail_call_max_exceed.c"
    r1 = r6;
#line 85 "sample/tail_call_max_exceed.c"
    r2 = POINTER(runtime_context->map_data[0].address);
#line 85 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(1);
#line 85 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 85 "sample/tail_call_max_exceed.c"
    if (r0 == 0) {
#line 85 "sample/tail_call_max_exceed.c"
        return 0;
#line 85 "sample/tail_call_max_exceed.c"
    }
#line 85 "sample/tail_call_max_exceed.c"
    if ((int64_t)r0 > IMMEDIATE(-1)) {
#line 85 "sample/tail_call_max_exceed.c"
        goto label_1;
#line 85 "sample/tail_call_max_exceed.c"
    }
#line 85 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-20));
#line 85 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1680154744);
#line 85 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-24));
#line 85 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7306085893296906528;
#line 85 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 85 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7234307576302018668;
#line 85 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 85 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099540;
#line 85 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 85 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 85 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 85 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(30);
#line 85 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(1);
#line 85 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
label_1:
#line 85 "sample/tail_call_max_exceed.c"
    r0 = IMMEDIATE(2);
#line 85 "sample/tail_call_max_exceed.c"
    return r0;
#line 85 "sample/tail_call_max_exceed.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sample_test_callee1_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     14,
     "helper_id_14",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
};

static GUID sample_test_callee1_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sample_test_callee1_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sample_test_callee1_maps[] = {
    0,
};

#pragma code_seg(push, "sampl~35")
static uint64_t
sample_test_callee1(void* context, const program_runtime_context_t* runtime_context)
#line 86 "sample/tail_call_max_exceed.c"
{
#line 86 "sample/tail_call_max_exceed.c"
    // Prologue.
#line 86 "sample/tail_call_max_exceed.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 86 "sample/tail_call_max_exceed.c"
    register uint64_t r0 = 0;
#line 86 "sample/tail_call_max_exceed.c"
    register uint64_t r1 = 0;
#line 86 "sample/tail_call_max_exceed.c"
    register uint64_t r2 = 0;
#line 86 "sample/tail_call_max_exceed.c"
    register uint64_t r3 = 0;
#line 86 "sample/tail_call_max_exceed.c"
    register uint64_t r4 = 0;
#line 86 "sample/tail_call_max_exceed.c"
    register uint64_t r5 = 0;
#line 86 "sample/tail_call_max_exceed.c"
    register uint64_t r6 = 0;
#line 86 "sample/tail_call_max_exceed.c"
    register uint64_t r7 = 0;
#line 86 "sample/tail_call_max_exceed.c"
    register uint64_t r10 = 0;

#line 86 "sample/tail_call_max_exceed.c"
    r1 = (uintptr_t)context;
#line 86 "sample/tail_call_max_exceed.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 86 "sample/tail_call_max_exceed.c"
    r6 = r1;
#line 86 "sample/tail_call_max_exceed.c"
    r7 = IMMEDIATE(10);
#line 86 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-4));
#line 86 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1566844192);
#line 86 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-8));
#line 86 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)4404574498340937772;
#line 86 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
#line 86 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)6729544563593082971;
#line 86 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 86 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2339731488442490988;
#line 86 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 86 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099572;
#line 86 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 86 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2334956330884555075;
#line 86 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 86 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 86 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 86 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(46);
#line 86 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(1);
#line 86 "sample/tail_call_max_exceed.c"
    r4 = IMMEDIATE(2);
#line 86 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 86 "sample/tail_call_max_exceed.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[0].address);
#line 86 "sample/tail_call_max_exceed.c"
    r1 = r6;
#line 86 "sample/tail_call_max_exceed.c"
    r2 = POINTER(runtime_context->map_data[0].address);
#line 86 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(2);
#line 86 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 86 "sample/tail_call_max_exceed.c"
    if (r0 == 0) {
#line 86 "sample/tail_call_max_exceed.c"
        return 0;
#line 86 "sample/tail_call_max_exceed.c"
    }
#line 86 "sample/tail_call_max_exceed.c"
    if ((int64_t)r0 > IMMEDIATE(-1)) {
#line 86 "sample/tail_call_max_exceed.c"
        goto label_1;
#line 86 "sample/tail_call_max_exceed.c"
    }
#line 86 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-20));
#line 86 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1680154744);
#line 86 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-24));
#line 86 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7306085893296906528;
#line 86 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 86 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7234307576302018668;
#line 86 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 86 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099540;
#line 86 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 86 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 86 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 86 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(30);
#line 86 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(2);
#line 86 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
label_1:
#line 86 "sample/tail_call_max_exceed.c"
    r0 = IMMEDIATE(2);
#line 86 "sample/tail_call_max_exceed.c"
    return r0;
#line 86 "sample/tail_call_max_exceed.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sample_test_callee10_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     14,
     "helper_id_14",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
};

static GUID sample_test_callee10_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sample_test_callee10_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sample_test_callee10_maps[] = {
    0,
};

#pragma code_seg(push, "sampl~26")
static uint64_t
sample_test_callee10(void* context, const program_runtime_context_t* runtime_context)
#line 95 "sample/tail_call_max_exceed.c"
{
#line 95 "sample/tail_call_max_exceed.c"
    // Prologue.
#line 95 "sample/tail_call_max_exceed.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 95 "sample/tail_call_max_exceed.c"
    register uint64_t r0 = 0;
#line 95 "sample/tail_call_max_exceed.c"
    register uint64_t r1 = 0;
#line 95 "sample/tail_call_max_exceed.c"
    register uint64_t r2 = 0;
#line 95 "sample/tail_call_max_exceed.c"
    register uint64_t r3 = 0;
#line 95 "sample/tail_call_max_exceed.c"
    register uint64_t r4 = 0;
#line 95 "sample/tail_call_max_exceed.c"
    register uint64_t r5 = 0;
#line 95 "sample/tail_call_max_exceed.c"
    register uint64_t r6 = 0;
#line 95 "sample/tail_call_max_exceed.c"
    register uint64_t r7 = 0;
#line 95 "sample/tail_call_max_exceed.c"
    register uint64_t r10 = 0;

#line 95 "sample/tail_call_max_exceed.c"
    r1 = (uintptr_t)context;
#line 95 "sample/tail_call_max_exceed.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 95 "sample/tail_call_max_exceed.c"
    r6 = r1;
#line 95 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1566844192);
#line 95 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-8));
#line 95 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)4404574498340937772;
#line 95 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
#line 95 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)6729544563593082971;
#line 95 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 95 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2339731488442490988;
#line 95 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 95 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099572;
#line 95 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 95 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2334956330884555075;
#line 95 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 95 "sample/tail_call_max_exceed.c"
    r7 = IMMEDIATE(10);
#line 95 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-4));
#line 95 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 95 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 95 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(46);
#line 95 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(10);
#line 95 "sample/tail_call_max_exceed.c"
    r4 = IMMEDIATE(11);
#line 95 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 95 "sample/tail_call_max_exceed.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[0].address);
#line 95 "sample/tail_call_max_exceed.c"
    r1 = r6;
#line 95 "sample/tail_call_max_exceed.c"
    r2 = POINTER(runtime_context->map_data[0].address);
#line 95 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(11);
#line 95 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 95 "sample/tail_call_max_exceed.c"
    if (r0 == 0) {
#line 95 "sample/tail_call_max_exceed.c"
        return 0;
#line 95 "sample/tail_call_max_exceed.c"
    }
#line 95 "sample/tail_call_max_exceed.c"
    if ((int64_t)r0 > IMMEDIATE(-1)) {
#line 95 "sample/tail_call_max_exceed.c"
        goto label_1;
#line 95 "sample/tail_call_max_exceed.c"
    }
#line 95 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-20));
#line 95 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1680154744);
#line 95 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-24));
#line 95 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7306085893296906528;
#line 95 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 95 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7234307576302018668;
#line 95 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 95 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099540;
#line 95 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 95 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 95 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 95 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(30);
#line 95 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(11);
#line 95 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
label_1:
#line 95 "sample/tail_call_max_exceed.c"
    r0 = IMMEDIATE(2);
#line 95 "sample/tail_call_max_exceed.c"
    return r0;
#line 95 "sample/tail_call_max_exceed.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sample_test_callee11_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     14,
     "helper_id_14",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
};

static GUID sample_test_callee11_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sample_test_callee11_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sample_test_callee11_maps[] = {
    0,
};

#pragma code_seg(push, "sampl~25")
static uint64_t
sample_test_callee11(void* context, const program_runtime_context_t* runtime_context)
#line 96 "sample/tail_call_max_exceed.c"
{
#line 96 "sample/tail_call_max_exceed.c"
    // Prologue.
#line 96 "sample/tail_call_max_exceed.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 96 "sample/tail_call_max_exceed.c"
    register uint64_t r0 = 0;
#line 96 "sample/tail_call_max_exceed.c"
    register uint64_t r1 = 0;
#line 96 "sample/tail_call_max_exceed.c"
    register uint64_t r2 = 0;
#line 96 "sample/tail_call_max_exceed.c"
    register uint64_t r3 = 0;
#line 96 "sample/tail_call_max_exceed.c"
    register uint64_t r4 = 0;
#line 96 "sample/tail_call_max_exceed.c"
    register uint64_t r5 = 0;
#line 96 "sample/tail_call_max_exceed.c"
    register uint64_t r6 = 0;
#line 96 "sample/tail_call_max_exceed.c"
    register uint64_t r7 = 0;
#line 96 "sample/tail_call_max_exceed.c"
    register uint64_t r10 = 0;

#line 96 "sample/tail_call_max_exceed.c"
    r1 = (uintptr_t)context;
#line 96 "sample/tail_call_max_exceed.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 96 "sample/tail_call_max_exceed.c"
    r6 = r1;
#line 96 "sample/tail_call_max_exceed.c"
    r7 = IMMEDIATE(10);
#line 96 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-4));
#line 96 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1566844192);
#line 96 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-8));
#line 96 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)4404574498340937772;
#line 96 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
#line 96 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)6729544563593082971;
#line 96 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 96 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2339731488442490988;
#line 96 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 96 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099572;
#line 96 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 96 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2334956330884555075;
#line 96 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 96 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 96 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 96 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(46);
#line 96 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(11);
#line 96 "sample/tail_call_max_exceed.c"
    r4 = IMMEDIATE(12);
#line 96 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 96 "sample/tail_call_max_exceed.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[0].address);
#line 96 "sample/tail_call_max_exceed.c"
    r1 = r6;
#line 96 "sample/tail_call_max_exceed.c"
    r2 = POINTER(runtime_context->map_data[0].address);
#line 96 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(12);
#line 96 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 96 "sample/tail_call_max_exceed.c"
    if (r0 == 0) {
#line 96 "sample/tail_call_max_exceed.c"
        return 0;
#line 96 "sample/tail_call_max_exceed.c"
    }
#line 96 "sample/tail_call_max_exceed.c"
    if ((int64_t)r0 > IMMEDIATE(-1)) {
#line 96 "sample/tail_call_max_exceed.c"
        goto label_1;
#line 96 "sample/tail_call_max_exceed.c"
    }
#line 96 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-20));
#line 96 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1680154744);
#line 96 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-24));
#line 96 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7306085893296906528;
#line 96 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 96 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7234307576302018668;
#line 96 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 96 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099540;
#line 96 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 96 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 96 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 96 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(30);
#line 96 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(12);
#line 96 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
label_1:
#line 96 "sample/tail_call_max_exceed.c"
    r0 = IMMEDIATE(2);
#line 96 "sample/tail_call_max_exceed.c"
    return r0;
#line 96 "sample/tail_call_max_exceed.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sample_test_callee12_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     14,
     "helper_id_14",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
};

static GUID sample_test_callee12_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sample_test_callee12_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sample_test_callee12_maps[] = {
    0,
};

#pragma code_seg(push, "sampl~24")
static uint64_t
sample_test_callee12(void* context, const program_runtime_context_t* runtime_context)
#line 97 "sample/tail_call_max_exceed.c"
{
#line 97 "sample/tail_call_max_exceed.c"
    // Prologue.
#line 97 "sample/tail_call_max_exceed.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 97 "sample/tail_call_max_exceed.c"
    register uint64_t r0 = 0;
#line 97 "sample/tail_call_max_exceed.c"
    register uint64_t r1 = 0;
#line 97 "sample/tail_call_max_exceed.c"
    register uint64_t r2 = 0;
#line 97 "sample/tail_call_max_exceed.c"
    register uint64_t r3 = 0;
#line 97 "sample/tail_call_max_exceed.c"
    register uint64_t r4 = 0;
#line 97 "sample/tail_call_max_exceed.c"
    register uint64_t r5 = 0;
#line 97 "sample/tail_call_max_exceed.c"
    register uint64_t r6 = 0;
#line 97 "sample/tail_call_max_exceed.c"
    register uint64_t r7 = 0;
#line 97 "sample/tail_call_max_exceed.c"
    register uint64_t r10 = 0;

#line 97 "sample/tail_call_max_exceed.c"
    r1 = (uintptr_t)context;
#line 97 "sample/tail_call_max_exceed.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 97 "sample/tail_call_max_exceed.c"
    r6 = r1;
#line 97 "sample/tail_call_max_exceed.c"
    r7 = IMMEDIATE(10);
#line 97 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-4));
#line 97 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1566844192);
#line 97 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-8));
#line 97 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)4404574498340937772;
#line 97 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
#line 97 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)6729544563593082971;
#line 97 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 97 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2339731488442490988;
#line 97 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 97 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099572;
#line 97 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 97 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2334956330884555075;
#line 97 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 97 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 97 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 97 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(46);
#line 97 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(12);
#line 97 "sample/tail_call_max_exceed.c"
    r4 = IMMEDIATE(13);
#line 97 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 97 "sample/tail_call_max_exceed.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[0].address);
#line 97 "sample/tail_call_max_exceed.c"
    r1 = r6;
#line 97 "sample/tail_call_max_exceed.c"
    r2 = POINTER(runtime_context->map_data[0].address);
#line 97 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(13);
#line 97 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 97 "sample/tail_call_max_exceed.c"
    if (r0 == 0) {
#line 97 "sample/tail_call_max_exceed.c"
        return 0;
#line 97 "sample/tail_call_max_exceed.c"
    }
#line 97 "sample/tail_call_max_exceed.c"
    if ((int64_t)r0 > IMMEDIATE(-1)) {
#line 97 "sample/tail_call_max_exceed.c"
        goto label_1;
#line 97 "sample/tail_call_max_exceed.c"
    }
#line 97 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-20));
#line 97 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1680154744);
#line 97 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-24));
#line 97 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7306085893296906528;
#line 97 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 97 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7234307576302018668;
#line 97 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 97 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099540;
#line 97 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 97 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 97 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 97 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(30);
#line 97 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(13);
#line 97 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
label_1:
#line 97 "sample/tail_call_max_exceed.c"
    r0 = IMMEDIATE(2);
#line 97 "sample/tail_call_max_exceed.c"
    return r0;
#line 97 "sample/tail_call_max_exceed.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sample_test_callee13_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     14,
     "helper_id_14",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
};

static GUID sample_test_callee13_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sample_test_callee13_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sample_test_callee13_maps[] = {
    0,
};

#pragma code_seg(push, "sampl~23")
static uint64_t
sample_test_callee13(void* context, const program_runtime_context_t* runtime_context)
#line 98 "sample/tail_call_max_exceed.c"
{
#line 98 "sample/tail_call_max_exceed.c"
    // Prologue.
#line 98 "sample/tail_call_max_exceed.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 98 "sample/tail_call_max_exceed.c"
    register uint64_t r0 = 0;
#line 98 "sample/tail_call_max_exceed.c"
    register uint64_t r1 = 0;
#line 98 "sample/tail_call_max_exceed.c"
    register uint64_t r2 = 0;
#line 98 "sample/tail_call_max_exceed.c"
    register uint64_t r3 = 0;
#line 98 "sample/tail_call_max_exceed.c"
    register uint64_t r4 = 0;
#line 98 "sample/tail_call_max_exceed.c"
    register uint64_t r5 = 0;
#line 98 "sample/tail_call_max_exceed.c"
    register uint64_t r6 = 0;
#line 98 "sample/tail_call_max_exceed.c"
    register uint64_t r7 = 0;
#line 98 "sample/tail_call_max_exceed.c"
    register uint64_t r10 = 0;

#line 98 "sample/tail_call_max_exceed.c"
    r1 = (uintptr_t)context;
#line 98 "sample/tail_call_max_exceed.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 98 "sample/tail_call_max_exceed.c"
    r6 = r1;
#line 98 "sample/tail_call_max_exceed.c"
    r7 = IMMEDIATE(10);
#line 98 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-4));
#line 98 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1566844192);
#line 98 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-8));
#line 98 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)4404574498340937772;
#line 98 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
#line 98 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)6729544563593082971;
#line 98 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 98 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2339731488442490988;
#line 98 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 98 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099572;
#line 98 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 98 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2334956330884555075;
#line 98 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 98 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 98 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 98 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(46);
#line 98 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(13);
#line 98 "sample/tail_call_max_exceed.c"
    r4 = IMMEDIATE(14);
#line 98 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 98 "sample/tail_call_max_exceed.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[0].address);
#line 98 "sample/tail_call_max_exceed.c"
    r1 = r6;
#line 98 "sample/tail_call_max_exceed.c"
    r2 = POINTER(runtime_context->map_data[0].address);
#line 98 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(14);
#line 98 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 98 "sample/tail_call_max_exceed.c"
    if (r0 == 0) {
#line 98 "sample/tail_call_max_exceed.c"
        return 0;
#line 98 "sample/tail_call_max_exceed.c"
    }
#line 98 "sample/tail_call_max_exceed.c"
    if ((int64_t)r0 > IMMEDIATE(-1)) {
#line 98 "sample/tail_call_max_exceed.c"
        goto label_1;
#line 98 "sample/tail_call_max_exceed.c"
    }
#line 98 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-20));
#line 98 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1680154744);
#line 98 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-24));
#line 98 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7306085893296906528;
#line 98 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 98 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7234307576302018668;
#line 98 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 98 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099540;
#line 98 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 98 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 98 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 98 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(30);
#line 98 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(14);
#line 98 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
label_1:
#line 98 "sample/tail_call_max_exceed.c"
    r0 = IMMEDIATE(2);
#line 98 "sample/tail_call_max_exceed.c"
    return r0;
#line 98 "sample/tail_call_max_exceed.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sample_test_callee14_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     14,
     "helper_id_14",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
};

static GUID sample_test_callee14_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sample_test_callee14_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sample_test_callee14_maps[] = {
    0,
};

#pragma code_seg(push, "sampl~22")
static uint64_t
sample_test_callee14(void* context, const program_runtime_context_t* runtime_context)
#line 99 "sample/tail_call_max_exceed.c"
{
#line 99 "sample/tail_call_max_exceed.c"
    // Prologue.
#line 99 "sample/tail_call_max_exceed.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 99 "sample/tail_call_max_exceed.c"
    register uint64_t r0 = 0;
#line 99 "sample/tail_call_max_exceed.c"
    register uint64_t r1 = 0;
#line 99 "sample/tail_call_max_exceed.c"
    register uint64_t r2 = 0;
#line 99 "sample/tail_call_max_exceed.c"
    register uint64_t r3 = 0;
#line 99 "sample/tail_call_max_exceed.c"
    register uint64_t r4 = 0;
#line 99 "sample/tail_call_max_exceed.c"
    register uint64_t r5 = 0;
#line 99 "sample/tail_call_max_exceed.c"
    register uint64_t r6 = 0;
#line 99 "sample/tail_call_max_exceed.c"
    register uint64_t r7 = 0;
#line 99 "sample/tail_call_max_exceed.c"
    register uint64_t r10 = 0;

#line 99 "sample/tail_call_max_exceed.c"
    r1 = (uintptr_t)context;
#line 99 "sample/tail_call_max_exceed.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 99 "sample/tail_call_max_exceed.c"
    r6 = r1;
#line 99 "sample/tail_call_max_exceed.c"
    r7 = IMMEDIATE(10);
#line 99 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-4));
#line 99 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1566844192);
#line 99 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-8));
#line 99 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)4404574498340937772;
#line 99 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
#line 99 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)6729544563593082971;
#line 99 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 99 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2339731488442490988;
#line 99 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 99 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099572;
#line 99 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 99 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2334956330884555075;
#line 99 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 99 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 99 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 99 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(46);
#line 99 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(14);
#line 99 "sample/tail_call_max_exceed.c"
    r4 = IMMEDIATE(15);
#line 99 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 99 "sample/tail_call_max_exceed.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[0].address);
#line 99 "sample/tail_call_max_exceed.c"
    r1 = r6;
#line 99 "sample/tail_call_max_exceed.c"
    r2 = POINTER(runtime_context->map_data[0].address);
#line 99 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(15);
#line 99 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 99 "sample/tail_call_max_exceed.c"
    if (r0 == 0) {
#line 99 "sample/tail_call_max_exceed.c"
        return 0;
#line 99 "sample/tail_call_max_exceed.c"
    }
#line 99 "sample/tail_call_max_exceed.c"
    if ((int64_t)r0 > IMMEDIATE(-1)) {
#line 99 "sample/tail_call_max_exceed.c"
        goto label_1;
#line 99 "sample/tail_call_max_exceed.c"
    }
#line 99 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-20));
#line 99 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1680154744);
#line 99 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-24));
#line 99 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7306085893296906528;
#line 99 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 99 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7234307576302018668;
#line 99 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 99 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099540;
#line 99 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 99 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 99 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 99 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(30);
#line 99 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(15);
#line 99 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
label_1:
#line 99 "sample/tail_call_max_exceed.c"
    r0 = IMMEDIATE(2);
#line 99 "sample/tail_call_max_exceed.c"
    return r0;
#line 99 "sample/tail_call_max_exceed.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sample_test_callee15_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     14,
     "helper_id_14",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
};

static GUID sample_test_callee15_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sample_test_callee15_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sample_test_callee15_maps[] = {
    0,
};

#pragma code_seg(push, "sampl~21")
static uint64_t
sample_test_callee15(void* context, const program_runtime_context_t* runtime_context)
#line 100 "sample/tail_call_max_exceed.c"
{
#line 100 "sample/tail_call_max_exceed.c"
    // Prologue.
#line 100 "sample/tail_call_max_exceed.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 100 "sample/tail_call_max_exceed.c"
    register uint64_t r0 = 0;
#line 100 "sample/tail_call_max_exceed.c"
    register uint64_t r1 = 0;
#line 100 "sample/tail_call_max_exceed.c"
    register uint64_t r2 = 0;
#line 100 "sample/tail_call_max_exceed.c"
    register uint64_t r3 = 0;
#line 100 "sample/tail_call_max_exceed.c"
    register uint64_t r4 = 0;
#line 100 "sample/tail_call_max_exceed.c"
    register uint64_t r5 = 0;
#line 100 "sample/tail_call_max_exceed.c"
    register uint64_t r6 = 0;
#line 100 "sample/tail_call_max_exceed.c"
    register uint64_t r7 = 0;
#line 100 "sample/tail_call_max_exceed.c"
    register uint64_t r10 = 0;

#line 100 "sample/tail_call_max_exceed.c"
    r1 = (uintptr_t)context;
#line 100 "sample/tail_call_max_exceed.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 100 "sample/tail_call_max_exceed.c"
    r6 = r1;
#line 100 "sample/tail_call_max_exceed.c"
    r7 = IMMEDIATE(10);
#line 100 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-4));
#line 100 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1566844192);
#line 100 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-8));
#line 100 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)4404574498340937772;
#line 100 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
#line 100 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)6729544563593082971;
#line 100 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 100 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2339731488442490988;
#line 100 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 100 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099572;
#line 100 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 100 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2334956330884555075;
#line 100 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 100 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 100 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 100 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(46);
#line 100 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(15);
#line 100 "sample/tail_call_max_exceed.c"
    r4 = IMMEDIATE(16);
#line 100 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 100 "sample/tail_call_max_exceed.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[0].address);
#line 100 "sample/tail_call_max_exceed.c"
    r1 = r6;
#line 100 "sample/tail_call_max_exceed.c"
    r2 = POINTER(runtime_context->map_data[0].address);
#line 100 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(16);
#line 100 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 100 "sample/tail_call_max_exceed.c"
    if (r0 == 0) {
#line 100 "sample/tail_call_max_exceed.c"
        return 0;
#line 100 "sample/tail_call_max_exceed.c"
    }
#line 100 "sample/tail_call_max_exceed.c"
    if ((int64_t)r0 > IMMEDIATE(-1)) {
#line 100 "sample/tail_call_max_exceed.c"
        goto label_1;
#line 100 "sample/tail_call_max_exceed.c"
    }
#line 100 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-20));
#line 100 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1680154744);
#line 100 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-24));
#line 100 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7306085893296906528;
#line 100 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 100 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7234307576302018668;
#line 100 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 100 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099540;
#line 100 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 100 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 100 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 100 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(30);
#line 100 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(16);
#line 100 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
label_1:
#line 100 "sample/tail_call_max_exceed.c"
    r0 = IMMEDIATE(2);
#line 100 "sample/tail_call_max_exceed.c"
    return r0;
#line 100 "sample/tail_call_max_exceed.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sample_test_callee16_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     14,
     "helper_id_14",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
};

static GUID sample_test_callee16_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sample_test_callee16_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sample_test_callee16_maps[] = {
    0,
};

#pragma code_seg(push, "sampl~20")
static uint64_t
sample_test_callee16(void* context, const program_runtime_context_t* runtime_context)
#line 101 "sample/tail_call_max_exceed.c"
{
#line 101 "sample/tail_call_max_exceed.c"
    // Prologue.
#line 101 "sample/tail_call_max_exceed.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 101 "sample/tail_call_max_exceed.c"
    register uint64_t r0 = 0;
#line 101 "sample/tail_call_max_exceed.c"
    register uint64_t r1 = 0;
#line 101 "sample/tail_call_max_exceed.c"
    register uint64_t r2 = 0;
#line 101 "sample/tail_call_max_exceed.c"
    register uint64_t r3 = 0;
#line 101 "sample/tail_call_max_exceed.c"
    register uint64_t r4 = 0;
#line 101 "sample/tail_call_max_exceed.c"
    register uint64_t r5 = 0;
#line 101 "sample/tail_call_max_exceed.c"
    register uint64_t r6 = 0;
#line 101 "sample/tail_call_max_exceed.c"
    register uint64_t r7 = 0;
#line 101 "sample/tail_call_max_exceed.c"
    register uint64_t r10 = 0;

#line 101 "sample/tail_call_max_exceed.c"
    r1 = (uintptr_t)context;
#line 101 "sample/tail_call_max_exceed.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 101 "sample/tail_call_max_exceed.c"
    r6 = r1;
#line 101 "sample/tail_call_max_exceed.c"
    r7 = IMMEDIATE(10);
#line 101 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-4));
#line 101 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1566844192);
#line 101 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-8));
#line 101 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)4404574498340937772;
#line 101 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
#line 101 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)6729544563593082971;
#line 101 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 101 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2339731488442490988;
#line 101 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 101 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099572;
#line 101 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 101 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2334956330884555075;
#line 101 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 101 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 101 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 101 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(46);
#line 101 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(16);
#line 101 "sample/tail_call_max_exceed.c"
    r4 = IMMEDIATE(17);
#line 101 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 101 "sample/tail_call_max_exceed.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[0].address);
#line 101 "sample/tail_call_max_exceed.c"
    r1 = r6;
#line 101 "sample/tail_call_max_exceed.c"
    r2 = POINTER(runtime_context->map_data[0].address);
#line 101 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(17);
#line 101 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 101 "sample/tail_call_max_exceed.c"
    if (r0 == 0) {
#line 101 "sample/tail_call_max_exceed.c"
        return 0;
#line 101 "sample/tail_call_max_exceed.c"
    }
#line 101 "sample/tail_call_max_exceed.c"
    if ((int64_t)r0 > IMMEDIATE(-1)) {
#line 101 "sample/tail_call_max_exceed.c"
        goto label_1;
#line 101 "sample/tail_call_max_exceed.c"
    }
#line 101 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-20));
#line 101 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1680154744);
#line 101 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-24));
#line 101 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7306085893296906528;
#line 101 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 101 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7234307576302018668;
#line 101 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 101 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099540;
#line 101 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 101 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 101 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 101 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(30);
#line 101 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(17);
#line 101 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
label_1:
#line 101 "sample/tail_call_max_exceed.c"
    r0 = IMMEDIATE(2);
#line 101 "sample/tail_call_max_exceed.c"
    return r0;
#line 101 "sample/tail_call_max_exceed.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sample_test_callee17_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     14,
     "helper_id_14",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
};

static GUID sample_test_callee17_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sample_test_callee17_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sample_test_callee17_maps[] = {
    0,
};

#pragma code_seg(push, "sampl~19")
static uint64_t
sample_test_callee17(void* context, const program_runtime_context_t* runtime_context)
#line 102 "sample/tail_call_max_exceed.c"
{
#line 102 "sample/tail_call_max_exceed.c"
    // Prologue.
#line 102 "sample/tail_call_max_exceed.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 102 "sample/tail_call_max_exceed.c"
    register uint64_t r0 = 0;
#line 102 "sample/tail_call_max_exceed.c"
    register uint64_t r1 = 0;
#line 102 "sample/tail_call_max_exceed.c"
    register uint64_t r2 = 0;
#line 102 "sample/tail_call_max_exceed.c"
    register uint64_t r3 = 0;
#line 102 "sample/tail_call_max_exceed.c"
    register uint64_t r4 = 0;
#line 102 "sample/tail_call_max_exceed.c"
    register uint64_t r5 = 0;
#line 102 "sample/tail_call_max_exceed.c"
    register uint64_t r6 = 0;
#line 102 "sample/tail_call_max_exceed.c"
    register uint64_t r7 = 0;
#line 102 "sample/tail_call_max_exceed.c"
    register uint64_t r10 = 0;

#line 102 "sample/tail_call_max_exceed.c"
    r1 = (uintptr_t)context;
#line 102 "sample/tail_call_max_exceed.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 102 "sample/tail_call_max_exceed.c"
    r6 = r1;
#line 102 "sample/tail_call_max_exceed.c"
    r7 = IMMEDIATE(10);
#line 102 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-4));
#line 102 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1566844192);
#line 102 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-8));
#line 102 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)4404574498340937772;
#line 102 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
#line 102 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)6729544563593082971;
#line 102 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 102 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2339731488442490988;
#line 102 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 102 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099572;
#line 102 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 102 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2334956330884555075;
#line 102 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 102 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 102 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 102 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(46);
#line 102 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(17);
#line 102 "sample/tail_call_max_exceed.c"
    r4 = IMMEDIATE(18);
#line 102 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 102 "sample/tail_call_max_exceed.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[0].address);
#line 102 "sample/tail_call_max_exceed.c"
    r1 = r6;
#line 102 "sample/tail_call_max_exceed.c"
    r2 = POINTER(runtime_context->map_data[0].address);
#line 102 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(18);
#line 102 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 102 "sample/tail_call_max_exceed.c"
    if (r0 == 0) {
#line 102 "sample/tail_call_max_exceed.c"
        return 0;
#line 102 "sample/tail_call_max_exceed.c"
    }
#line 102 "sample/tail_call_max_exceed.c"
    if ((int64_t)r0 > IMMEDIATE(-1)) {
#line 102 "sample/tail_call_max_exceed.c"
        goto label_1;
#line 102 "sample/tail_call_max_exceed.c"
    }
#line 102 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-20));
#line 102 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1680154744);
#line 102 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-24));
#line 102 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7306085893296906528;
#line 102 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 102 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7234307576302018668;
#line 102 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 102 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099540;
#line 102 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 102 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 102 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 102 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(30);
#line 102 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(18);
#line 102 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
label_1:
#line 102 "sample/tail_call_max_exceed.c"
    r0 = IMMEDIATE(2);
#line 102 "sample/tail_call_max_exceed.c"
    return r0;
#line 102 "sample/tail_call_max_exceed.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sample_test_callee18_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     14,
     "helper_id_14",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
};

static GUID sample_test_callee18_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sample_test_callee18_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sample_test_callee18_maps[] = {
    0,
};

#pragma code_seg(push, "sampl~18")
static uint64_t
sample_test_callee18(void* context, const program_runtime_context_t* runtime_context)
#line 103 "sample/tail_call_max_exceed.c"
{
#line 103 "sample/tail_call_max_exceed.c"
    // Prologue.
#line 103 "sample/tail_call_max_exceed.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 103 "sample/tail_call_max_exceed.c"
    register uint64_t r0 = 0;
#line 103 "sample/tail_call_max_exceed.c"
    register uint64_t r1 = 0;
#line 103 "sample/tail_call_max_exceed.c"
    register uint64_t r2 = 0;
#line 103 "sample/tail_call_max_exceed.c"
    register uint64_t r3 = 0;
#line 103 "sample/tail_call_max_exceed.c"
    register uint64_t r4 = 0;
#line 103 "sample/tail_call_max_exceed.c"
    register uint64_t r5 = 0;
#line 103 "sample/tail_call_max_exceed.c"
    register uint64_t r6 = 0;
#line 103 "sample/tail_call_max_exceed.c"
    register uint64_t r7 = 0;
#line 103 "sample/tail_call_max_exceed.c"
    register uint64_t r10 = 0;

#line 103 "sample/tail_call_max_exceed.c"
    r1 = (uintptr_t)context;
#line 103 "sample/tail_call_max_exceed.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 103 "sample/tail_call_max_exceed.c"
    r6 = r1;
#line 103 "sample/tail_call_max_exceed.c"
    r7 = IMMEDIATE(10);
#line 103 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-4));
#line 103 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1566844192);
#line 103 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-8));
#line 103 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)4404574498340937772;
#line 103 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
#line 103 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)6729544563593082971;
#line 103 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 103 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2339731488442490988;
#line 103 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 103 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099572;
#line 103 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 103 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2334956330884555075;
#line 103 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 103 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 103 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 103 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(46);
#line 103 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(18);
#line 103 "sample/tail_call_max_exceed.c"
    r4 = IMMEDIATE(19);
#line 103 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 103 "sample/tail_call_max_exceed.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[0].address);
#line 103 "sample/tail_call_max_exceed.c"
    r1 = r6;
#line 103 "sample/tail_call_max_exceed.c"
    r2 = POINTER(runtime_context->map_data[0].address);
#line 103 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(19);
#line 103 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 103 "sample/tail_call_max_exceed.c"
    if (r0 == 0) {
#line 103 "sample/tail_call_max_exceed.c"
        return 0;
#line 103 "sample/tail_call_max_exceed.c"
    }
#line 103 "sample/tail_call_max_exceed.c"
    if ((int64_t)r0 > IMMEDIATE(-1)) {
#line 103 "sample/tail_call_max_exceed.c"
        goto label_1;
#line 103 "sample/tail_call_max_exceed.c"
    }
#line 103 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-20));
#line 103 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1680154744);
#line 103 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-24));
#line 103 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7306085893296906528;
#line 103 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 103 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7234307576302018668;
#line 103 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 103 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099540;
#line 103 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 103 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 103 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 103 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(30);
#line 103 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(19);
#line 103 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
label_1:
#line 103 "sample/tail_call_max_exceed.c"
    r0 = IMMEDIATE(2);
#line 103 "sample/tail_call_max_exceed.c"
    return r0;
#line 103 "sample/tail_call_max_exceed.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sample_test_callee19_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     14,
     "helper_id_14",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
};

static GUID sample_test_callee19_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sample_test_callee19_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sample_test_callee19_maps[] = {
    0,
};

#pragma code_seg(push, "sampl~17")
static uint64_t
sample_test_callee19(void* context, const program_runtime_context_t* runtime_context)
#line 104 "sample/tail_call_max_exceed.c"
{
#line 104 "sample/tail_call_max_exceed.c"
    // Prologue.
#line 104 "sample/tail_call_max_exceed.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 104 "sample/tail_call_max_exceed.c"
    register uint64_t r0 = 0;
#line 104 "sample/tail_call_max_exceed.c"
    register uint64_t r1 = 0;
#line 104 "sample/tail_call_max_exceed.c"
    register uint64_t r2 = 0;
#line 104 "sample/tail_call_max_exceed.c"
    register uint64_t r3 = 0;
#line 104 "sample/tail_call_max_exceed.c"
    register uint64_t r4 = 0;
#line 104 "sample/tail_call_max_exceed.c"
    register uint64_t r5 = 0;
#line 104 "sample/tail_call_max_exceed.c"
    register uint64_t r6 = 0;
#line 104 "sample/tail_call_max_exceed.c"
    register uint64_t r7 = 0;
#line 104 "sample/tail_call_max_exceed.c"
    register uint64_t r10 = 0;

#line 104 "sample/tail_call_max_exceed.c"
    r1 = (uintptr_t)context;
#line 104 "sample/tail_call_max_exceed.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 104 "sample/tail_call_max_exceed.c"
    r6 = r1;
#line 104 "sample/tail_call_max_exceed.c"
    r7 = IMMEDIATE(10);
#line 104 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-4));
#line 104 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1566844192);
#line 104 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-8));
#line 104 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)4404574498340937772;
#line 104 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
#line 104 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)6729544563593082971;
#line 104 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 104 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2339731488442490988;
#line 104 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 104 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099572;
#line 104 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 104 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2334956330884555075;
#line 104 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 104 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 104 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 104 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(46);
#line 104 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(19);
#line 104 "sample/tail_call_max_exceed.c"
    r4 = IMMEDIATE(20);
#line 104 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 104 "sample/tail_call_max_exceed.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[0].address);
#line 104 "sample/tail_call_max_exceed.c"
    r1 = r6;
#line 104 "sample/tail_call_max_exceed.c"
    r2 = POINTER(runtime_context->map_data[0].address);
#line 104 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(20);
#line 104 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 104 "sample/tail_call_max_exceed.c"
    if (r0 == 0) {
#line 104 "sample/tail_call_max_exceed.c"
        return 0;
#line 104 "sample/tail_call_max_exceed.c"
    }
#line 104 "sample/tail_call_max_exceed.c"
    if ((int64_t)r0 > IMMEDIATE(-1)) {
#line 104 "sample/tail_call_max_exceed.c"
        goto label_1;
#line 104 "sample/tail_call_max_exceed.c"
    }
#line 104 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-20));
#line 104 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1680154744);
#line 104 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-24));
#line 104 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7306085893296906528;
#line 104 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 104 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7234307576302018668;
#line 104 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 104 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099540;
#line 104 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 104 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 104 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 104 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(30);
#line 104 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(20);
#line 104 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
label_1:
#line 104 "sample/tail_call_max_exceed.c"
    r0 = IMMEDIATE(2);
#line 104 "sample/tail_call_max_exceed.c"
    return r0;
#line 104 "sample/tail_call_max_exceed.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sample_test_callee2_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     14,
     "helper_id_14",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
};

static GUID sample_test_callee2_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sample_test_callee2_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sample_test_callee2_maps[] = {
    0,
};

#pragma code_seg(push, "sampl~34")
static uint64_t
sample_test_callee2(void* context, const program_runtime_context_t* runtime_context)
#line 87 "sample/tail_call_max_exceed.c"
{
#line 87 "sample/tail_call_max_exceed.c"
    // Prologue.
#line 87 "sample/tail_call_max_exceed.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 87 "sample/tail_call_max_exceed.c"
    register uint64_t r0 = 0;
#line 87 "sample/tail_call_max_exceed.c"
    register uint64_t r1 = 0;
#line 87 "sample/tail_call_max_exceed.c"
    register uint64_t r2 = 0;
#line 87 "sample/tail_call_max_exceed.c"
    register uint64_t r3 = 0;
#line 87 "sample/tail_call_max_exceed.c"
    register uint64_t r4 = 0;
#line 87 "sample/tail_call_max_exceed.c"
    register uint64_t r5 = 0;
#line 87 "sample/tail_call_max_exceed.c"
    register uint64_t r6 = 0;
#line 87 "sample/tail_call_max_exceed.c"
    register uint64_t r7 = 0;
#line 87 "sample/tail_call_max_exceed.c"
    register uint64_t r10 = 0;

#line 87 "sample/tail_call_max_exceed.c"
    r1 = (uintptr_t)context;
#line 87 "sample/tail_call_max_exceed.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 87 "sample/tail_call_max_exceed.c"
    r6 = r1;
#line 87 "sample/tail_call_max_exceed.c"
    r7 = IMMEDIATE(10);
#line 87 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-4));
#line 87 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1566844192);
#line 87 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-8));
#line 87 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)4404574498340937772;
#line 87 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
#line 87 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)6729544563593082971;
#line 87 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 87 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2339731488442490988;
#line 87 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 87 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099572;
#line 87 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 87 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2334956330884555075;
#line 87 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 87 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 87 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 87 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(46);
#line 87 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(2);
#line 87 "sample/tail_call_max_exceed.c"
    r4 = IMMEDIATE(3);
#line 87 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 87 "sample/tail_call_max_exceed.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[0].address);
#line 87 "sample/tail_call_max_exceed.c"
    r1 = r6;
#line 87 "sample/tail_call_max_exceed.c"
    r2 = POINTER(runtime_context->map_data[0].address);
#line 87 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(3);
#line 87 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 87 "sample/tail_call_max_exceed.c"
    if (r0 == 0) {
#line 87 "sample/tail_call_max_exceed.c"
        return 0;
#line 87 "sample/tail_call_max_exceed.c"
    }
#line 87 "sample/tail_call_max_exceed.c"
    if ((int64_t)r0 > IMMEDIATE(-1)) {
#line 87 "sample/tail_call_max_exceed.c"
        goto label_1;
#line 87 "sample/tail_call_max_exceed.c"
    }
#line 87 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-20));
#line 87 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1680154744);
#line 87 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-24));
#line 87 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7306085893296906528;
#line 87 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 87 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7234307576302018668;
#line 87 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 87 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099540;
#line 87 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 87 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 87 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 87 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(30);
#line 87 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(3);
#line 87 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
label_1:
#line 87 "sample/tail_call_max_exceed.c"
    r0 = IMMEDIATE(2);
#line 87 "sample/tail_call_max_exceed.c"
    return r0;
#line 87 "sample/tail_call_max_exceed.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sample_test_callee20_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     14,
     "helper_id_14",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
};

static GUID sample_test_callee20_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sample_test_callee20_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sample_test_callee20_maps[] = {
    0,
};

#pragma code_seg(push, "sampl~16")
static uint64_t
sample_test_callee20(void* context, const program_runtime_context_t* runtime_context)
#line 105 "sample/tail_call_max_exceed.c"
{
#line 105 "sample/tail_call_max_exceed.c"
    // Prologue.
#line 105 "sample/tail_call_max_exceed.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 105 "sample/tail_call_max_exceed.c"
    register uint64_t r0 = 0;
#line 105 "sample/tail_call_max_exceed.c"
    register uint64_t r1 = 0;
#line 105 "sample/tail_call_max_exceed.c"
    register uint64_t r2 = 0;
#line 105 "sample/tail_call_max_exceed.c"
    register uint64_t r3 = 0;
#line 105 "sample/tail_call_max_exceed.c"
    register uint64_t r4 = 0;
#line 105 "sample/tail_call_max_exceed.c"
    register uint64_t r5 = 0;
#line 105 "sample/tail_call_max_exceed.c"
    register uint64_t r6 = 0;
#line 105 "sample/tail_call_max_exceed.c"
    register uint64_t r7 = 0;
#line 105 "sample/tail_call_max_exceed.c"
    register uint64_t r10 = 0;

#line 105 "sample/tail_call_max_exceed.c"
    r1 = (uintptr_t)context;
#line 105 "sample/tail_call_max_exceed.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 105 "sample/tail_call_max_exceed.c"
    r6 = r1;
#line 105 "sample/tail_call_max_exceed.c"
    r7 = IMMEDIATE(10);
#line 105 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-4));
#line 105 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1566844192);
#line 105 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-8));
#line 105 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)4404574498340937772;
#line 105 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
#line 105 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)6729544563593082971;
#line 105 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 105 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2339731488442490988;
#line 105 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 105 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099572;
#line 105 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 105 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2334956330884555075;
#line 105 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 105 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 105 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 105 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(46);
#line 105 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(20);
#line 105 "sample/tail_call_max_exceed.c"
    r4 = IMMEDIATE(21);
#line 105 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 105 "sample/tail_call_max_exceed.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[0].address);
#line 105 "sample/tail_call_max_exceed.c"
    r1 = r6;
#line 105 "sample/tail_call_max_exceed.c"
    r2 = POINTER(runtime_context->map_data[0].address);
#line 105 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(21);
#line 105 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 105 "sample/tail_call_max_exceed.c"
    if (r0 == 0) {
#line 105 "sample/tail_call_max_exceed.c"
        return 0;
#line 105 "sample/tail_call_max_exceed.c"
    }
#line 105 "sample/tail_call_max_exceed.c"
    if ((int64_t)r0 > IMMEDIATE(-1)) {
#line 105 "sample/tail_call_max_exceed.c"
        goto label_1;
#line 105 "sample/tail_call_max_exceed.c"
    }
#line 105 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-20));
#line 105 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1680154744);
#line 105 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-24));
#line 105 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7306085893296906528;
#line 105 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 105 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7234307576302018668;
#line 105 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 105 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099540;
#line 105 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 105 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 105 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 105 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(30);
#line 105 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(21);
#line 105 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
label_1:
#line 105 "sample/tail_call_max_exceed.c"
    r0 = IMMEDIATE(2);
#line 105 "sample/tail_call_max_exceed.c"
    return r0;
#line 105 "sample/tail_call_max_exceed.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sample_test_callee21_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     14,
     "helper_id_14",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
};

static GUID sample_test_callee21_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sample_test_callee21_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sample_test_callee21_maps[] = {
    0,
};

#pragma code_seg(push, "sampl~15")
static uint64_t
sample_test_callee21(void* context, const program_runtime_context_t* runtime_context)
#line 106 "sample/tail_call_max_exceed.c"
{
#line 106 "sample/tail_call_max_exceed.c"
    // Prologue.
#line 106 "sample/tail_call_max_exceed.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 106 "sample/tail_call_max_exceed.c"
    register uint64_t r0 = 0;
#line 106 "sample/tail_call_max_exceed.c"
    register uint64_t r1 = 0;
#line 106 "sample/tail_call_max_exceed.c"
    register uint64_t r2 = 0;
#line 106 "sample/tail_call_max_exceed.c"
    register uint64_t r3 = 0;
#line 106 "sample/tail_call_max_exceed.c"
    register uint64_t r4 = 0;
#line 106 "sample/tail_call_max_exceed.c"
    register uint64_t r5 = 0;
#line 106 "sample/tail_call_max_exceed.c"
    register uint64_t r6 = 0;
#line 106 "sample/tail_call_max_exceed.c"
    register uint64_t r7 = 0;
#line 106 "sample/tail_call_max_exceed.c"
    register uint64_t r10 = 0;

#line 106 "sample/tail_call_max_exceed.c"
    r1 = (uintptr_t)context;
#line 106 "sample/tail_call_max_exceed.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 106 "sample/tail_call_max_exceed.c"
    r6 = r1;
#line 106 "sample/tail_call_max_exceed.c"
    r7 = IMMEDIATE(10);
#line 106 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-4));
#line 106 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1566844192);
#line 106 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-8));
#line 106 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)4404574498340937772;
#line 106 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
#line 106 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)6729544563593082971;
#line 106 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 106 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2339731488442490988;
#line 106 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 106 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099572;
#line 106 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 106 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2334956330884555075;
#line 106 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 106 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 106 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 106 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(46);
#line 106 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(21);
#line 106 "sample/tail_call_max_exceed.c"
    r4 = IMMEDIATE(22);
#line 106 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 106 "sample/tail_call_max_exceed.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[0].address);
#line 106 "sample/tail_call_max_exceed.c"
    r1 = r6;
#line 106 "sample/tail_call_max_exceed.c"
    r2 = POINTER(runtime_context->map_data[0].address);
#line 106 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(22);
#line 106 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 106 "sample/tail_call_max_exceed.c"
    if (r0 == 0) {
#line 106 "sample/tail_call_max_exceed.c"
        return 0;
#line 106 "sample/tail_call_max_exceed.c"
    }
#line 106 "sample/tail_call_max_exceed.c"
    if ((int64_t)r0 > IMMEDIATE(-1)) {
#line 106 "sample/tail_call_max_exceed.c"
        goto label_1;
#line 106 "sample/tail_call_max_exceed.c"
    }
#line 106 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-20));
#line 106 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1680154744);
#line 106 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-24));
#line 106 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7306085893296906528;
#line 106 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 106 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7234307576302018668;
#line 106 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 106 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099540;
#line 106 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 106 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 106 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 106 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(30);
#line 106 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(22);
#line 106 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
label_1:
#line 106 "sample/tail_call_max_exceed.c"
    r0 = IMMEDIATE(2);
#line 106 "sample/tail_call_max_exceed.c"
    return r0;
#line 106 "sample/tail_call_max_exceed.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sample_test_callee22_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     14,
     "helper_id_14",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
};

static GUID sample_test_callee22_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sample_test_callee22_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sample_test_callee22_maps[] = {
    0,
};

#pragma code_seg(push, "sampl~14")
static uint64_t
sample_test_callee22(void* context, const program_runtime_context_t* runtime_context)
#line 107 "sample/tail_call_max_exceed.c"
{
#line 107 "sample/tail_call_max_exceed.c"
    // Prologue.
#line 107 "sample/tail_call_max_exceed.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 107 "sample/tail_call_max_exceed.c"
    register uint64_t r0 = 0;
#line 107 "sample/tail_call_max_exceed.c"
    register uint64_t r1 = 0;
#line 107 "sample/tail_call_max_exceed.c"
    register uint64_t r2 = 0;
#line 107 "sample/tail_call_max_exceed.c"
    register uint64_t r3 = 0;
#line 107 "sample/tail_call_max_exceed.c"
    register uint64_t r4 = 0;
#line 107 "sample/tail_call_max_exceed.c"
    register uint64_t r5 = 0;
#line 107 "sample/tail_call_max_exceed.c"
    register uint64_t r6 = 0;
#line 107 "sample/tail_call_max_exceed.c"
    register uint64_t r7 = 0;
#line 107 "sample/tail_call_max_exceed.c"
    register uint64_t r10 = 0;

#line 107 "sample/tail_call_max_exceed.c"
    r1 = (uintptr_t)context;
#line 107 "sample/tail_call_max_exceed.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 107 "sample/tail_call_max_exceed.c"
    r6 = r1;
#line 107 "sample/tail_call_max_exceed.c"
    r7 = IMMEDIATE(10);
#line 107 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-4));
#line 107 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1566844192);
#line 107 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-8));
#line 107 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)4404574498340937772;
#line 107 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
#line 107 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)6729544563593082971;
#line 107 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 107 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2339731488442490988;
#line 107 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 107 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099572;
#line 107 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 107 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2334956330884555075;
#line 107 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 107 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 107 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 107 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(46);
#line 107 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(22);
#line 107 "sample/tail_call_max_exceed.c"
    r4 = IMMEDIATE(23);
#line 107 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 107 "sample/tail_call_max_exceed.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[0].address);
#line 107 "sample/tail_call_max_exceed.c"
    r1 = r6;
#line 107 "sample/tail_call_max_exceed.c"
    r2 = POINTER(runtime_context->map_data[0].address);
#line 107 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(23);
#line 107 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 107 "sample/tail_call_max_exceed.c"
    if (r0 == 0) {
#line 107 "sample/tail_call_max_exceed.c"
        return 0;
#line 107 "sample/tail_call_max_exceed.c"
    }
#line 107 "sample/tail_call_max_exceed.c"
    if ((int64_t)r0 > IMMEDIATE(-1)) {
#line 107 "sample/tail_call_max_exceed.c"
        goto label_1;
#line 107 "sample/tail_call_max_exceed.c"
    }
#line 107 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-20));
#line 107 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1680154744);
#line 107 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-24));
#line 107 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7306085893296906528;
#line 107 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 107 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7234307576302018668;
#line 107 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 107 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099540;
#line 107 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 107 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 107 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 107 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(30);
#line 107 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(23);
#line 107 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
label_1:
#line 107 "sample/tail_call_max_exceed.c"
    r0 = IMMEDIATE(2);
#line 107 "sample/tail_call_max_exceed.c"
    return r0;
#line 107 "sample/tail_call_max_exceed.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sample_test_callee23_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     14,
     "helper_id_14",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
};

static GUID sample_test_callee23_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sample_test_callee23_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sample_test_callee23_maps[] = {
    0,
};

#pragma code_seg(push, "sampl~13")
static uint64_t
sample_test_callee23(void* context, const program_runtime_context_t* runtime_context)
#line 108 "sample/tail_call_max_exceed.c"
{
#line 108 "sample/tail_call_max_exceed.c"
    // Prologue.
#line 108 "sample/tail_call_max_exceed.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 108 "sample/tail_call_max_exceed.c"
    register uint64_t r0 = 0;
#line 108 "sample/tail_call_max_exceed.c"
    register uint64_t r1 = 0;
#line 108 "sample/tail_call_max_exceed.c"
    register uint64_t r2 = 0;
#line 108 "sample/tail_call_max_exceed.c"
    register uint64_t r3 = 0;
#line 108 "sample/tail_call_max_exceed.c"
    register uint64_t r4 = 0;
#line 108 "sample/tail_call_max_exceed.c"
    register uint64_t r5 = 0;
#line 108 "sample/tail_call_max_exceed.c"
    register uint64_t r6 = 0;
#line 108 "sample/tail_call_max_exceed.c"
    register uint64_t r7 = 0;
#line 108 "sample/tail_call_max_exceed.c"
    register uint64_t r10 = 0;

#line 108 "sample/tail_call_max_exceed.c"
    r1 = (uintptr_t)context;
#line 108 "sample/tail_call_max_exceed.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 108 "sample/tail_call_max_exceed.c"
    r6 = r1;
#line 108 "sample/tail_call_max_exceed.c"
    r7 = IMMEDIATE(10);
#line 108 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-4));
#line 108 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1566844192);
#line 108 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-8));
#line 108 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)4404574498340937772;
#line 108 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
#line 108 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)6729544563593082971;
#line 108 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 108 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2339731488442490988;
#line 108 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 108 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099572;
#line 108 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 108 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2334956330884555075;
#line 108 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 108 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 108 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 108 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(46);
#line 108 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(23);
#line 108 "sample/tail_call_max_exceed.c"
    r4 = IMMEDIATE(24);
#line 108 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 108 "sample/tail_call_max_exceed.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[0].address);
#line 108 "sample/tail_call_max_exceed.c"
    r1 = r6;
#line 108 "sample/tail_call_max_exceed.c"
    r2 = POINTER(runtime_context->map_data[0].address);
#line 108 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(24);
#line 108 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 108 "sample/tail_call_max_exceed.c"
    if (r0 == 0) {
#line 108 "sample/tail_call_max_exceed.c"
        return 0;
#line 108 "sample/tail_call_max_exceed.c"
    }
#line 108 "sample/tail_call_max_exceed.c"
    if ((int64_t)r0 > IMMEDIATE(-1)) {
#line 108 "sample/tail_call_max_exceed.c"
        goto label_1;
#line 108 "sample/tail_call_max_exceed.c"
    }
#line 108 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-20));
#line 108 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1680154744);
#line 108 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-24));
#line 108 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7306085893296906528;
#line 108 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 108 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7234307576302018668;
#line 108 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 108 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099540;
#line 108 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 108 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 108 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 108 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(30);
#line 108 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(24);
#line 108 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
label_1:
#line 108 "sample/tail_call_max_exceed.c"
    r0 = IMMEDIATE(2);
#line 108 "sample/tail_call_max_exceed.c"
    return r0;
#line 108 "sample/tail_call_max_exceed.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sample_test_callee24_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     14,
     "helper_id_14",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
};

static GUID sample_test_callee24_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sample_test_callee24_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sample_test_callee24_maps[] = {
    0,
};

#pragma code_seg(push, "sampl~12")
static uint64_t
sample_test_callee24(void* context, const program_runtime_context_t* runtime_context)
#line 109 "sample/tail_call_max_exceed.c"
{
#line 109 "sample/tail_call_max_exceed.c"
    // Prologue.
#line 109 "sample/tail_call_max_exceed.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 109 "sample/tail_call_max_exceed.c"
    register uint64_t r0 = 0;
#line 109 "sample/tail_call_max_exceed.c"
    register uint64_t r1 = 0;
#line 109 "sample/tail_call_max_exceed.c"
    register uint64_t r2 = 0;
#line 109 "sample/tail_call_max_exceed.c"
    register uint64_t r3 = 0;
#line 109 "sample/tail_call_max_exceed.c"
    register uint64_t r4 = 0;
#line 109 "sample/tail_call_max_exceed.c"
    register uint64_t r5 = 0;
#line 109 "sample/tail_call_max_exceed.c"
    register uint64_t r6 = 0;
#line 109 "sample/tail_call_max_exceed.c"
    register uint64_t r7 = 0;
#line 109 "sample/tail_call_max_exceed.c"
    register uint64_t r10 = 0;

#line 109 "sample/tail_call_max_exceed.c"
    r1 = (uintptr_t)context;
#line 109 "sample/tail_call_max_exceed.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 109 "sample/tail_call_max_exceed.c"
    r6 = r1;
#line 109 "sample/tail_call_max_exceed.c"
    r7 = IMMEDIATE(10);
#line 109 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-4));
#line 109 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1566844192);
#line 109 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-8));
#line 109 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)4404574498340937772;
#line 109 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
#line 109 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)6729544563593082971;
#line 109 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 109 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2339731488442490988;
#line 109 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 109 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099572;
#line 109 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 109 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2334956330884555075;
#line 109 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 109 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 109 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 109 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(46);
#line 109 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(24);
#line 109 "sample/tail_call_max_exceed.c"
    r4 = IMMEDIATE(25);
#line 109 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 109 "sample/tail_call_max_exceed.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[0].address);
#line 109 "sample/tail_call_max_exceed.c"
    r1 = r6;
#line 109 "sample/tail_call_max_exceed.c"
    r2 = POINTER(runtime_context->map_data[0].address);
#line 109 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(25);
#line 109 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 109 "sample/tail_call_max_exceed.c"
    if (r0 == 0) {
#line 109 "sample/tail_call_max_exceed.c"
        return 0;
#line 109 "sample/tail_call_max_exceed.c"
    }
#line 109 "sample/tail_call_max_exceed.c"
    if ((int64_t)r0 > IMMEDIATE(-1)) {
#line 109 "sample/tail_call_max_exceed.c"
        goto label_1;
#line 109 "sample/tail_call_max_exceed.c"
    }
#line 109 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-20));
#line 109 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1680154744);
#line 109 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-24));
#line 109 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7306085893296906528;
#line 109 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 109 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7234307576302018668;
#line 109 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 109 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099540;
#line 109 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 109 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 109 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 109 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(30);
#line 109 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(25);
#line 109 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
label_1:
#line 109 "sample/tail_call_max_exceed.c"
    r0 = IMMEDIATE(2);
#line 109 "sample/tail_call_max_exceed.c"
    return r0;
#line 109 "sample/tail_call_max_exceed.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sample_test_callee25_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     14,
     "helper_id_14",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
};

static GUID sample_test_callee25_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sample_test_callee25_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sample_test_callee25_maps[] = {
    0,
};

#pragma code_seg(push, "sampl~11")
static uint64_t
sample_test_callee25(void* context, const program_runtime_context_t* runtime_context)
#line 110 "sample/tail_call_max_exceed.c"
{
#line 110 "sample/tail_call_max_exceed.c"
    // Prologue.
#line 110 "sample/tail_call_max_exceed.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 110 "sample/tail_call_max_exceed.c"
    register uint64_t r0 = 0;
#line 110 "sample/tail_call_max_exceed.c"
    register uint64_t r1 = 0;
#line 110 "sample/tail_call_max_exceed.c"
    register uint64_t r2 = 0;
#line 110 "sample/tail_call_max_exceed.c"
    register uint64_t r3 = 0;
#line 110 "sample/tail_call_max_exceed.c"
    register uint64_t r4 = 0;
#line 110 "sample/tail_call_max_exceed.c"
    register uint64_t r5 = 0;
#line 110 "sample/tail_call_max_exceed.c"
    register uint64_t r6 = 0;
#line 110 "sample/tail_call_max_exceed.c"
    register uint64_t r7 = 0;
#line 110 "sample/tail_call_max_exceed.c"
    register uint64_t r10 = 0;

#line 110 "sample/tail_call_max_exceed.c"
    r1 = (uintptr_t)context;
#line 110 "sample/tail_call_max_exceed.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 110 "sample/tail_call_max_exceed.c"
    r6 = r1;
#line 110 "sample/tail_call_max_exceed.c"
    r7 = IMMEDIATE(10);
#line 110 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-4));
#line 110 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1566844192);
#line 110 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-8));
#line 110 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)4404574498340937772;
#line 110 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
#line 110 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)6729544563593082971;
#line 110 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 110 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2339731488442490988;
#line 110 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 110 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099572;
#line 110 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 110 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2334956330884555075;
#line 110 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 110 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 110 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 110 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(46);
#line 110 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(25);
#line 110 "sample/tail_call_max_exceed.c"
    r4 = IMMEDIATE(26);
#line 110 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 110 "sample/tail_call_max_exceed.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[0].address);
#line 110 "sample/tail_call_max_exceed.c"
    r1 = r6;
#line 110 "sample/tail_call_max_exceed.c"
    r2 = POINTER(runtime_context->map_data[0].address);
#line 110 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(26);
#line 110 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 110 "sample/tail_call_max_exceed.c"
    if (r0 == 0) {
#line 110 "sample/tail_call_max_exceed.c"
        return 0;
#line 110 "sample/tail_call_max_exceed.c"
    }
#line 110 "sample/tail_call_max_exceed.c"
    if ((int64_t)r0 > IMMEDIATE(-1)) {
#line 110 "sample/tail_call_max_exceed.c"
        goto label_1;
#line 110 "sample/tail_call_max_exceed.c"
    }
#line 110 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-20));
#line 110 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1680154744);
#line 110 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-24));
#line 110 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7306085893296906528;
#line 110 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 110 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7234307576302018668;
#line 110 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 110 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099540;
#line 110 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 110 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 110 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 110 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(30);
#line 110 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(26);
#line 110 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
label_1:
#line 110 "sample/tail_call_max_exceed.c"
    r0 = IMMEDIATE(2);
#line 110 "sample/tail_call_max_exceed.c"
    return r0;
#line 110 "sample/tail_call_max_exceed.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sample_test_callee26_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     14,
     "helper_id_14",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
};

static GUID sample_test_callee26_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sample_test_callee26_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sample_test_callee26_maps[] = {
    0,
};

#pragma code_seg(push, "sampl~10")
static uint64_t
sample_test_callee26(void* context, const program_runtime_context_t* runtime_context)
#line 111 "sample/tail_call_max_exceed.c"
{
#line 111 "sample/tail_call_max_exceed.c"
    // Prologue.
#line 111 "sample/tail_call_max_exceed.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 111 "sample/tail_call_max_exceed.c"
    register uint64_t r0 = 0;
#line 111 "sample/tail_call_max_exceed.c"
    register uint64_t r1 = 0;
#line 111 "sample/tail_call_max_exceed.c"
    register uint64_t r2 = 0;
#line 111 "sample/tail_call_max_exceed.c"
    register uint64_t r3 = 0;
#line 111 "sample/tail_call_max_exceed.c"
    register uint64_t r4 = 0;
#line 111 "sample/tail_call_max_exceed.c"
    register uint64_t r5 = 0;
#line 111 "sample/tail_call_max_exceed.c"
    register uint64_t r6 = 0;
#line 111 "sample/tail_call_max_exceed.c"
    register uint64_t r7 = 0;
#line 111 "sample/tail_call_max_exceed.c"
    register uint64_t r10 = 0;

#line 111 "sample/tail_call_max_exceed.c"
    r1 = (uintptr_t)context;
#line 111 "sample/tail_call_max_exceed.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 111 "sample/tail_call_max_exceed.c"
    r6 = r1;
#line 111 "sample/tail_call_max_exceed.c"
    r7 = IMMEDIATE(10);
#line 111 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-4));
#line 111 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1566844192);
#line 111 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-8));
#line 111 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)4404574498340937772;
#line 111 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
#line 111 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)6729544563593082971;
#line 111 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 111 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2339731488442490988;
#line 111 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 111 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099572;
#line 111 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 111 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2334956330884555075;
#line 111 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 111 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 111 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 111 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(46);
#line 111 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(26);
#line 111 "sample/tail_call_max_exceed.c"
    r4 = IMMEDIATE(27);
#line 111 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 111 "sample/tail_call_max_exceed.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[0].address);
#line 111 "sample/tail_call_max_exceed.c"
    r1 = r6;
#line 111 "sample/tail_call_max_exceed.c"
    r2 = POINTER(runtime_context->map_data[0].address);
#line 111 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(27);
#line 111 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 111 "sample/tail_call_max_exceed.c"
    if (r0 == 0) {
#line 111 "sample/tail_call_max_exceed.c"
        return 0;
#line 111 "sample/tail_call_max_exceed.c"
    }
#line 111 "sample/tail_call_max_exceed.c"
    if ((int64_t)r0 > IMMEDIATE(-1)) {
#line 111 "sample/tail_call_max_exceed.c"
        goto label_1;
#line 111 "sample/tail_call_max_exceed.c"
    }
#line 111 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-20));
#line 111 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1680154744);
#line 111 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-24));
#line 111 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7306085893296906528;
#line 111 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 111 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7234307576302018668;
#line 111 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 111 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099540;
#line 111 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 111 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 111 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 111 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(30);
#line 111 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(27);
#line 111 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
label_1:
#line 111 "sample/tail_call_max_exceed.c"
    r0 = IMMEDIATE(2);
#line 111 "sample/tail_call_max_exceed.c"
    return r0;
#line 111 "sample/tail_call_max_exceed.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sample_test_callee27_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     14,
     "helper_id_14",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
};

static GUID sample_test_callee27_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sample_test_callee27_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sample_test_callee27_maps[] = {
    0,
};

#pragma code_seg(push, "sample~9")
static uint64_t
sample_test_callee27(void* context, const program_runtime_context_t* runtime_context)
#line 112 "sample/tail_call_max_exceed.c"
{
#line 112 "sample/tail_call_max_exceed.c"
    // Prologue.
#line 112 "sample/tail_call_max_exceed.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 112 "sample/tail_call_max_exceed.c"
    register uint64_t r0 = 0;
#line 112 "sample/tail_call_max_exceed.c"
    register uint64_t r1 = 0;
#line 112 "sample/tail_call_max_exceed.c"
    register uint64_t r2 = 0;
#line 112 "sample/tail_call_max_exceed.c"
    register uint64_t r3 = 0;
#line 112 "sample/tail_call_max_exceed.c"
    register uint64_t r4 = 0;
#line 112 "sample/tail_call_max_exceed.c"
    register uint64_t r5 = 0;
#line 112 "sample/tail_call_max_exceed.c"
    register uint64_t r6 = 0;
#line 112 "sample/tail_call_max_exceed.c"
    register uint64_t r7 = 0;
#line 112 "sample/tail_call_max_exceed.c"
    register uint64_t r10 = 0;

#line 112 "sample/tail_call_max_exceed.c"
    r1 = (uintptr_t)context;
#line 112 "sample/tail_call_max_exceed.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 112 "sample/tail_call_max_exceed.c"
    r6 = r1;
#line 112 "sample/tail_call_max_exceed.c"
    r7 = IMMEDIATE(10);
#line 112 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-4));
#line 112 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1566844192);
#line 112 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-8));
#line 112 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)4404574498340937772;
#line 112 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
#line 112 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)6729544563593082971;
#line 112 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 112 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2339731488442490988;
#line 112 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 112 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099572;
#line 112 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 112 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2334956330884555075;
#line 112 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 112 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 112 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 112 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(46);
#line 112 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(27);
#line 112 "sample/tail_call_max_exceed.c"
    r4 = IMMEDIATE(28);
#line 112 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 112 "sample/tail_call_max_exceed.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[0].address);
#line 112 "sample/tail_call_max_exceed.c"
    r1 = r6;
#line 112 "sample/tail_call_max_exceed.c"
    r2 = POINTER(runtime_context->map_data[0].address);
#line 112 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(28);
#line 112 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 112 "sample/tail_call_max_exceed.c"
    if (r0 == 0) {
#line 112 "sample/tail_call_max_exceed.c"
        return 0;
#line 112 "sample/tail_call_max_exceed.c"
    }
#line 112 "sample/tail_call_max_exceed.c"
    if ((int64_t)r0 > IMMEDIATE(-1)) {
#line 112 "sample/tail_call_max_exceed.c"
        goto label_1;
#line 112 "sample/tail_call_max_exceed.c"
    }
#line 112 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-20));
#line 112 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1680154744);
#line 112 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-24));
#line 112 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7306085893296906528;
#line 112 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 112 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7234307576302018668;
#line 112 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 112 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099540;
#line 112 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 112 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 112 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 112 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(30);
#line 112 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(28);
#line 112 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
label_1:
#line 112 "sample/tail_call_max_exceed.c"
    r0 = IMMEDIATE(2);
#line 112 "sample/tail_call_max_exceed.c"
    return r0;
#line 112 "sample/tail_call_max_exceed.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sample_test_callee28_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     14,
     "helper_id_14",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
};

static GUID sample_test_callee28_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sample_test_callee28_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sample_test_callee28_maps[] = {
    0,
};

#pragma code_seg(push, "sample~8")
static uint64_t
sample_test_callee28(void* context, const program_runtime_context_t* runtime_context)
#line 113 "sample/tail_call_max_exceed.c"
{
#line 113 "sample/tail_call_max_exceed.c"
    // Prologue.
#line 113 "sample/tail_call_max_exceed.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 113 "sample/tail_call_max_exceed.c"
    register uint64_t r0 = 0;
#line 113 "sample/tail_call_max_exceed.c"
    register uint64_t r1 = 0;
#line 113 "sample/tail_call_max_exceed.c"
    register uint64_t r2 = 0;
#line 113 "sample/tail_call_max_exceed.c"
    register uint64_t r3 = 0;
#line 113 "sample/tail_call_max_exceed.c"
    register uint64_t r4 = 0;
#line 113 "sample/tail_call_max_exceed.c"
    register uint64_t r5 = 0;
#line 113 "sample/tail_call_max_exceed.c"
    register uint64_t r6 = 0;
#line 113 "sample/tail_call_max_exceed.c"
    register uint64_t r7 = 0;
#line 113 "sample/tail_call_max_exceed.c"
    register uint64_t r10 = 0;

#line 113 "sample/tail_call_max_exceed.c"
    r1 = (uintptr_t)context;
#line 113 "sample/tail_call_max_exceed.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 113 "sample/tail_call_max_exceed.c"
    r6 = r1;
#line 113 "sample/tail_call_max_exceed.c"
    r7 = IMMEDIATE(10);
#line 113 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-4));
#line 113 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1566844192);
#line 113 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-8));
#line 113 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)4404574498340937772;
#line 113 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
#line 113 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)6729544563593082971;
#line 113 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 113 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2339731488442490988;
#line 113 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 113 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099572;
#line 113 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 113 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2334956330884555075;
#line 113 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 113 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 113 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 113 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(46);
#line 113 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(28);
#line 113 "sample/tail_call_max_exceed.c"
    r4 = IMMEDIATE(29);
#line 113 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 113 "sample/tail_call_max_exceed.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[0].address);
#line 113 "sample/tail_call_max_exceed.c"
    r1 = r6;
#line 113 "sample/tail_call_max_exceed.c"
    r2 = POINTER(runtime_context->map_data[0].address);
#line 113 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(29);
#line 113 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 113 "sample/tail_call_max_exceed.c"
    if (r0 == 0) {
#line 113 "sample/tail_call_max_exceed.c"
        return 0;
#line 113 "sample/tail_call_max_exceed.c"
    }
#line 113 "sample/tail_call_max_exceed.c"
    if ((int64_t)r0 > IMMEDIATE(-1)) {
#line 113 "sample/tail_call_max_exceed.c"
        goto label_1;
#line 113 "sample/tail_call_max_exceed.c"
    }
#line 113 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-20));
#line 113 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1680154744);
#line 113 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-24));
#line 113 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7306085893296906528;
#line 113 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 113 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7234307576302018668;
#line 113 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 113 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099540;
#line 113 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 113 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 113 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 113 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(30);
#line 113 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(29);
#line 113 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
label_1:
#line 113 "sample/tail_call_max_exceed.c"
    r0 = IMMEDIATE(2);
#line 113 "sample/tail_call_max_exceed.c"
    return r0;
#line 113 "sample/tail_call_max_exceed.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sample_test_callee29_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     14,
     "helper_id_14",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
};

static GUID sample_test_callee29_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sample_test_callee29_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sample_test_callee29_maps[] = {
    0,
};

#pragma code_seg(push, "sample~7")
static uint64_t
sample_test_callee29(void* context, const program_runtime_context_t* runtime_context)
#line 114 "sample/tail_call_max_exceed.c"
{
#line 114 "sample/tail_call_max_exceed.c"
    // Prologue.
#line 114 "sample/tail_call_max_exceed.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 114 "sample/tail_call_max_exceed.c"
    register uint64_t r0 = 0;
#line 114 "sample/tail_call_max_exceed.c"
    register uint64_t r1 = 0;
#line 114 "sample/tail_call_max_exceed.c"
    register uint64_t r2 = 0;
#line 114 "sample/tail_call_max_exceed.c"
    register uint64_t r3 = 0;
#line 114 "sample/tail_call_max_exceed.c"
    register uint64_t r4 = 0;
#line 114 "sample/tail_call_max_exceed.c"
    register uint64_t r5 = 0;
#line 114 "sample/tail_call_max_exceed.c"
    register uint64_t r6 = 0;
#line 114 "sample/tail_call_max_exceed.c"
    register uint64_t r7 = 0;
#line 114 "sample/tail_call_max_exceed.c"
    register uint64_t r10 = 0;

#line 114 "sample/tail_call_max_exceed.c"
    r1 = (uintptr_t)context;
#line 114 "sample/tail_call_max_exceed.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 114 "sample/tail_call_max_exceed.c"
    r6 = r1;
#line 114 "sample/tail_call_max_exceed.c"
    r7 = IMMEDIATE(10);
#line 114 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-4));
#line 114 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1566844192);
#line 114 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-8));
#line 114 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)4404574498340937772;
#line 114 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
#line 114 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)6729544563593082971;
#line 114 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 114 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2339731488442490988;
#line 114 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 114 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099572;
#line 114 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 114 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2334956330884555075;
#line 114 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 114 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 114 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 114 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(46);
#line 114 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(29);
#line 114 "sample/tail_call_max_exceed.c"
    r4 = IMMEDIATE(30);
#line 114 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 114 "sample/tail_call_max_exceed.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[0].address);
#line 114 "sample/tail_call_max_exceed.c"
    r1 = r6;
#line 114 "sample/tail_call_max_exceed.c"
    r2 = POINTER(runtime_context->map_data[0].address);
#line 114 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(30);
#line 114 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 114 "sample/tail_call_max_exceed.c"
    if (r0 == 0) {
#line 114 "sample/tail_call_max_exceed.c"
        return 0;
#line 114 "sample/tail_call_max_exceed.c"
    }
#line 114 "sample/tail_call_max_exceed.c"
    if ((int64_t)r0 > IMMEDIATE(-1)) {
#line 114 "sample/tail_call_max_exceed.c"
        goto label_1;
#line 114 "sample/tail_call_max_exceed.c"
    }
#line 114 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-20));
#line 114 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1680154744);
#line 114 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-24));
#line 114 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7306085893296906528;
#line 114 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 114 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7234307576302018668;
#line 114 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 114 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099540;
#line 114 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 114 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 114 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 114 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(30);
#line 114 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(30);
#line 114 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
label_1:
#line 114 "sample/tail_call_max_exceed.c"
    r0 = IMMEDIATE(2);
#line 114 "sample/tail_call_max_exceed.c"
    return r0;
#line 114 "sample/tail_call_max_exceed.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sample_test_callee3_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     14,
     "helper_id_14",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
};

static GUID sample_test_callee3_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sample_test_callee3_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sample_test_callee3_maps[] = {
    0,
};

#pragma code_seg(push, "sampl~33")
static uint64_t
sample_test_callee3(void* context, const program_runtime_context_t* runtime_context)
#line 88 "sample/tail_call_max_exceed.c"
{
#line 88 "sample/tail_call_max_exceed.c"
    // Prologue.
#line 88 "sample/tail_call_max_exceed.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 88 "sample/tail_call_max_exceed.c"
    register uint64_t r0 = 0;
#line 88 "sample/tail_call_max_exceed.c"
    register uint64_t r1 = 0;
#line 88 "sample/tail_call_max_exceed.c"
    register uint64_t r2 = 0;
#line 88 "sample/tail_call_max_exceed.c"
    register uint64_t r3 = 0;
#line 88 "sample/tail_call_max_exceed.c"
    register uint64_t r4 = 0;
#line 88 "sample/tail_call_max_exceed.c"
    register uint64_t r5 = 0;
#line 88 "sample/tail_call_max_exceed.c"
    register uint64_t r6 = 0;
#line 88 "sample/tail_call_max_exceed.c"
    register uint64_t r7 = 0;
#line 88 "sample/tail_call_max_exceed.c"
    register uint64_t r10 = 0;

#line 88 "sample/tail_call_max_exceed.c"
    r1 = (uintptr_t)context;
#line 88 "sample/tail_call_max_exceed.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 88 "sample/tail_call_max_exceed.c"
    r6 = r1;
#line 88 "sample/tail_call_max_exceed.c"
    r7 = IMMEDIATE(10);
#line 88 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-4));
#line 88 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1566844192);
#line 88 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-8));
#line 88 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)4404574498340937772;
#line 88 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
#line 88 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)6729544563593082971;
#line 88 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 88 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2339731488442490988;
#line 88 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 88 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099572;
#line 88 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 88 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2334956330884555075;
#line 88 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 88 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 88 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 88 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(46);
#line 88 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(3);
#line 88 "sample/tail_call_max_exceed.c"
    r4 = IMMEDIATE(4);
#line 88 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 88 "sample/tail_call_max_exceed.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[0].address);
#line 88 "sample/tail_call_max_exceed.c"
    r1 = r6;
#line 88 "sample/tail_call_max_exceed.c"
    r2 = POINTER(runtime_context->map_data[0].address);
#line 88 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(4);
#line 88 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 88 "sample/tail_call_max_exceed.c"
    if (r0 == 0) {
#line 88 "sample/tail_call_max_exceed.c"
        return 0;
#line 88 "sample/tail_call_max_exceed.c"
    }
#line 88 "sample/tail_call_max_exceed.c"
    if ((int64_t)r0 > IMMEDIATE(-1)) {
#line 88 "sample/tail_call_max_exceed.c"
        goto label_1;
#line 88 "sample/tail_call_max_exceed.c"
    }
#line 88 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-20));
#line 88 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1680154744);
#line 88 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-24));
#line 88 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7306085893296906528;
#line 88 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 88 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7234307576302018668;
#line 88 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 88 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099540;
#line 88 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 88 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 88 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 88 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(30);
#line 88 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(4);
#line 88 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
label_1:
#line 88 "sample/tail_call_max_exceed.c"
    r0 = IMMEDIATE(2);
#line 88 "sample/tail_call_max_exceed.c"
    return r0;
#line 88 "sample/tail_call_max_exceed.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sample_test_callee30_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     14,
     "helper_id_14",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
};

static GUID sample_test_callee30_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sample_test_callee30_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sample_test_callee30_maps[] = {
    0,
};

#pragma code_seg(push, "sample~6")
static uint64_t
sample_test_callee30(void* context, const program_runtime_context_t* runtime_context)
#line 115 "sample/tail_call_max_exceed.c"
{
#line 115 "sample/tail_call_max_exceed.c"
    // Prologue.
#line 115 "sample/tail_call_max_exceed.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 115 "sample/tail_call_max_exceed.c"
    register uint64_t r0 = 0;
#line 115 "sample/tail_call_max_exceed.c"
    register uint64_t r1 = 0;
#line 115 "sample/tail_call_max_exceed.c"
    register uint64_t r2 = 0;
#line 115 "sample/tail_call_max_exceed.c"
    register uint64_t r3 = 0;
#line 115 "sample/tail_call_max_exceed.c"
    register uint64_t r4 = 0;
#line 115 "sample/tail_call_max_exceed.c"
    register uint64_t r5 = 0;
#line 115 "sample/tail_call_max_exceed.c"
    register uint64_t r6 = 0;
#line 115 "sample/tail_call_max_exceed.c"
    register uint64_t r7 = 0;
#line 115 "sample/tail_call_max_exceed.c"
    register uint64_t r10 = 0;

#line 115 "sample/tail_call_max_exceed.c"
    r1 = (uintptr_t)context;
#line 115 "sample/tail_call_max_exceed.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 115 "sample/tail_call_max_exceed.c"
    r6 = r1;
#line 115 "sample/tail_call_max_exceed.c"
    r7 = IMMEDIATE(10);
#line 115 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-4));
#line 115 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1566844192);
#line 115 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-8));
#line 115 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)4404574498340937772;
#line 115 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
#line 115 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)6729544563593082971;
#line 115 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 115 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2339731488442490988;
#line 115 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 115 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099572;
#line 115 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 115 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2334956330884555075;
#line 115 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 115 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 115 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 115 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(46);
#line 115 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(30);
#line 115 "sample/tail_call_max_exceed.c"
    r4 = IMMEDIATE(31);
#line 115 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 115 "sample/tail_call_max_exceed.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[0].address);
#line 115 "sample/tail_call_max_exceed.c"
    r1 = r6;
#line 115 "sample/tail_call_max_exceed.c"
    r2 = POINTER(runtime_context->map_data[0].address);
#line 115 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(31);
#line 115 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 115 "sample/tail_call_max_exceed.c"
    if (r0 == 0) {
#line 115 "sample/tail_call_max_exceed.c"
        return 0;
#line 115 "sample/tail_call_max_exceed.c"
    }
#line 115 "sample/tail_call_max_exceed.c"
    if ((int64_t)r0 > IMMEDIATE(-1)) {
#line 115 "sample/tail_call_max_exceed.c"
        goto label_1;
#line 115 "sample/tail_call_max_exceed.c"
    }
#line 115 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-20));
#line 115 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1680154744);
#line 115 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-24));
#line 115 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7306085893296906528;
#line 115 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 115 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7234307576302018668;
#line 115 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 115 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099540;
#line 115 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 115 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 115 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 115 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(30);
#line 115 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(31);
#line 115 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
label_1:
#line 115 "sample/tail_call_max_exceed.c"
    r0 = IMMEDIATE(2);
#line 115 "sample/tail_call_max_exceed.c"
    return r0;
#line 115 "sample/tail_call_max_exceed.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sample_test_callee31_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     14,
     "helper_id_14",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
};

static GUID sample_test_callee31_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sample_test_callee31_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sample_test_callee31_maps[] = {
    0,
};

#pragma code_seg(push, "sample~5")
static uint64_t
sample_test_callee31(void* context, const program_runtime_context_t* runtime_context)
#line 116 "sample/tail_call_max_exceed.c"
{
#line 116 "sample/tail_call_max_exceed.c"
    // Prologue.
#line 116 "sample/tail_call_max_exceed.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 116 "sample/tail_call_max_exceed.c"
    register uint64_t r0 = 0;
#line 116 "sample/tail_call_max_exceed.c"
    register uint64_t r1 = 0;
#line 116 "sample/tail_call_max_exceed.c"
    register uint64_t r2 = 0;
#line 116 "sample/tail_call_max_exceed.c"
    register uint64_t r3 = 0;
#line 116 "sample/tail_call_max_exceed.c"
    register uint64_t r4 = 0;
#line 116 "sample/tail_call_max_exceed.c"
    register uint64_t r5 = 0;
#line 116 "sample/tail_call_max_exceed.c"
    register uint64_t r6 = 0;
#line 116 "sample/tail_call_max_exceed.c"
    register uint64_t r7 = 0;
#line 116 "sample/tail_call_max_exceed.c"
    register uint64_t r10 = 0;

#line 116 "sample/tail_call_max_exceed.c"
    r1 = (uintptr_t)context;
#line 116 "sample/tail_call_max_exceed.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 116 "sample/tail_call_max_exceed.c"
    r6 = r1;
#line 116 "sample/tail_call_max_exceed.c"
    r7 = IMMEDIATE(10);
#line 116 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-4));
#line 116 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1566844192);
#line 116 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-8));
#line 116 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)4404574498340937772;
#line 116 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
#line 116 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)6729544563593082971;
#line 116 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 116 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2339731488442490988;
#line 116 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 116 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099572;
#line 116 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 116 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2334956330884555075;
#line 116 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 116 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 116 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 116 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(46);
#line 116 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(31);
#line 116 "sample/tail_call_max_exceed.c"
    r4 = IMMEDIATE(32);
#line 116 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 116 "sample/tail_call_max_exceed.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[0].address);
#line 116 "sample/tail_call_max_exceed.c"
    r1 = r6;
#line 116 "sample/tail_call_max_exceed.c"
    r2 = POINTER(runtime_context->map_data[0].address);
#line 116 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(32);
#line 116 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 116 "sample/tail_call_max_exceed.c"
    if (r0 == 0) {
#line 116 "sample/tail_call_max_exceed.c"
        return 0;
#line 116 "sample/tail_call_max_exceed.c"
    }
#line 116 "sample/tail_call_max_exceed.c"
    if ((int64_t)r0 > IMMEDIATE(-1)) {
#line 116 "sample/tail_call_max_exceed.c"
        goto label_1;
#line 116 "sample/tail_call_max_exceed.c"
    }
#line 116 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-20));
#line 116 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1680154744);
#line 116 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-24));
#line 116 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7306085893296906528;
#line 116 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 116 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7234307576302018668;
#line 116 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 116 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099540;
#line 116 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 116 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 116 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 116 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(30);
#line 116 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(32);
#line 116 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
label_1:
#line 116 "sample/tail_call_max_exceed.c"
    r0 = IMMEDIATE(2);
#line 116 "sample/tail_call_max_exceed.c"
    return r0;
#line 116 "sample/tail_call_max_exceed.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sample_test_callee32_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     14,
     "helper_id_14",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
};

static GUID sample_test_callee32_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sample_test_callee32_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sample_test_callee32_maps[] = {
    0,
};

#pragma code_seg(push, "sample~4")
static uint64_t
sample_test_callee32(void* context, const program_runtime_context_t* runtime_context)
#line 117 "sample/tail_call_max_exceed.c"
{
#line 117 "sample/tail_call_max_exceed.c"
    // Prologue.
#line 117 "sample/tail_call_max_exceed.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 117 "sample/tail_call_max_exceed.c"
    register uint64_t r0 = 0;
#line 117 "sample/tail_call_max_exceed.c"
    register uint64_t r1 = 0;
#line 117 "sample/tail_call_max_exceed.c"
    register uint64_t r2 = 0;
#line 117 "sample/tail_call_max_exceed.c"
    register uint64_t r3 = 0;
#line 117 "sample/tail_call_max_exceed.c"
    register uint64_t r4 = 0;
#line 117 "sample/tail_call_max_exceed.c"
    register uint64_t r5 = 0;
#line 117 "sample/tail_call_max_exceed.c"
    register uint64_t r6 = 0;
#line 117 "sample/tail_call_max_exceed.c"
    register uint64_t r7 = 0;
#line 117 "sample/tail_call_max_exceed.c"
    register uint64_t r10 = 0;

#line 117 "sample/tail_call_max_exceed.c"
    r1 = (uintptr_t)context;
#line 117 "sample/tail_call_max_exceed.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 117 "sample/tail_call_max_exceed.c"
    r6 = r1;
#line 117 "sample/tail_call_max_exceed.c"
    r7 = IMMEDIATE(10);
#line 117 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-4));
#line 117 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1566844192);
#line 117 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-8));
#line 117 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)4404574498340937772;
#line 117 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
#line 117 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)6729544563593082971;
#line 117 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 117 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2339731488442490988;
#line 117 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 117 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099572;
#line 117 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 117 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2334956330884555075;
#line 117 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 117 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 117 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 117 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(46);
#line 117 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(32);
#line 117 "sample/tail_call_max_exceed.c"
    r4 = IMMEDIATE(33);
#line 117 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 117 "sample/tail_call_max_exceed.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[0].address);
#line 117 "sample/tail_call_max_exceed.c"
    r1 = r6;
#line 117 "sample/tail_call_max_exceed.c"
    r2 = POINTER(runtime_context->map_data[0].address);
#line 117 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(33);
#line 117 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 117 "sample/tail_call_max_exceed.c"
    if (r0 == 0) {
#line 117 "sample/tail_call_max_exceed.c"
        return 0;
#line 117 "sample/tail_call_max_exceed.c"
    }
#line 117 "sample/tail_call_max_exceed.c"
    if ((int64_t)r0 > IMMEDIATE(-1)) {
#line 117 "sample/tail_call_max_exceed.c"
        goto label_1;
#line 117 "sample/tail_call_max_exceed.c"
    }
#line 117 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-20));
#line 117 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1680154744);
#line 117 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-24));
#line 117 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7306085893296906528;
#line 117 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 117 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7234307576302018668;
#line 117 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 117 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099540;
#line 117 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 117 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 117 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 117 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(30);
#line 117 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(33);
#line 117 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
label_1:
#line 117 "sample/tail_call_max_exceed.c"
    r0 = IMMEDIATE(2);
#line 117 "sample/tail_call_max_exceed.c"
    return r0;
#line 117 "sample/tail_call_max_exceed.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sample_test_callee33_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     14,
     "helper_id_14",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
};

static GUID sample_test_callee33_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sample_test_callee33_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sample_test_callee33_maps[] = {
    0,
};

#pragma code_seg(push, "sample~3")
static uint64_t
sample_test_callee33(void* context, const program_runtime_context_t* runtime_context)
#line 118 "sample/tail_call_max_exceed.c"
{
#line 118 "sample/tail_call_max_exceed.c"
    // Prologue.
#line 118 "sample/tail_call_max_exceed.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 118 "sample/tail_call_max_exceed.c"
    register uint64_t r0 = 0;
#line 118 "sample/tail_call_max_exceed.c"
    register uint64_t r1 = 0;
#line 118 "sample/tail_call_max_exceed.c"
    register uint64_t r2 = 0;
#line 118 "sample/tail_call_max_exceed.c"
    register uint64_t r3 = 0;
#line 118 "sample/tail_call_max_exceed.c"
    register uint64_t r4 = 0;
#line 118 "sample/tail_call_max_exceed.c"
    register uint64_t r5 = 0;
#line 118 "sample/tail_call_max_exceed.c"
    register uint64_t r6 = 0;
#line 118 "sample/tail_call_max_exceed.c"
    register uint64_t r7 = 0;
#line 118 "sample/tail_call_max_exceed.c"
    register uint64_t r10 = 0;

#line 118 "sample/tail_call_max_exceed.c"
    r1 = (uintptr_t)context;
#line 118 "sample/tail_call_max_exceed.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 118 "sample/tail_call_max_exceed.c"
    r6 = r1;
#line 118 "sample/tail_call_max_exceed.c"
    r7 = IMMEDIATE(10);
#line 118 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-4));
#line 118 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1566844192);
#line 118 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-8));
#line 118 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)4404574498340937772;
#line 118 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
#line 118 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)6729544563593082971;
#line 118 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 118 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2339731488442490988;
#line 118 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 118 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099572;
#line 118 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 118 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2334956330884555075;
#line 118 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 118 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 118 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 118 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(46);
#line 118 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(33);
#line 118 "sample/tail_call_max_exceed.c"
    r4 = IMMEDIATE(34);
#line 118 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 118 "sample/tail_call_max_exceed.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[0].address);
#line 118 "sample/tail_call_max_exceed.c"
    r1 = r6;
#line 118 "sample/tail_call_max_exceed.c"
    r2 = POINTER(runtime_context->map_data[0].address);
#line 118 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(34);
#line 118 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 118 "sample/tail_call_max_exceed.c"
    if (r0 == 0) {
#line 118 "sample/tail_call_max_exceed.c"
        return 0;
#line 118 "sample/tail_call_max_exceed.c"
    }
#line 118 "sample/tail_call_max_exceed.c"
    if ((int64_t)r0 > IMMEDIATE(-1)) {
#line 118 "sample/tail_call_max_exceed.c"
        goto label_1;
#line 118 "sample/tail_call_max_exceed.c"
    }
#line 118 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-20));
#line 118 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1680154744);
#line 118 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-24));
#line 118 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7306085893296906528;
#line 118 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 118 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7234307576302018668;
#line 118 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 118 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099540;
#line 118 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 118 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 118 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 118 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(30);
#line 118 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(34);
#line 118 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
label_1:
#line 118 "sample/tail_call_max_exceed.c"
    r0 = IMMEDIATE(2);
#line 118 "sample/tail_call_max_exceed.c"
    return r0;
#line 118 "sample/tail_call_max_exceed.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sample_test_callee34_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     12,
     "helper_id_12",
    },
};

static GUID sample_test_callee34_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sample_test_callee34_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
#pragma code_seg(push, "sample~2")
static uint64_t
sample_test_callee34(void* context, const program_runtime_context_t* runtime_context)
#line 136 "sample/tail_call_max_exceed.c"
{
#line 136 "sample/tail_call_max_exceed.c"
    // Prologue.
#line 136 "sample/tail_call_max_exceed.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 136 "sample/tail_call_max_exceed.c"
    register uint64_t r0 = 0;
#line 136 "sample/tail_call_max_exceed.c"
    register uint64_t r1 = 0;
#line 136 "sample/tail_call_max_exceed.c"
    register uint64_t r2 = 0;
#line 136 "sample/tail_call_max_exceed.c"
    register uint64_t r3 = 0;
#line 136 "sample/tail_call_max_exceed.c"
    register uint64_t r4 = 0;
#line 136 "sample/tail_call_max_exceed.c"
    register uint64_t r5 = 0;
#line 136 "sample/tail_call_max_exceed.c"
    register uint64_t r10 = 0;

#line 136 "sample/tail_call_max_exceed.c"
    r1 = (uintptr_t)context;
#line 136 "sample/tail_call_max_exceed.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 136 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(668723);
#line 138 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-8));
#line 138 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7306365183224668020;
#line 138 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
#line 138 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)8315180240081809517;
#line 138 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 138 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7021991679500837998;
#line 138 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 138 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7575173785983328364;
#line 138 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 138 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7593478129464861004;
#line 138 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 138 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 138 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 138 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(44);
#line 138 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 139 "sample/tail_call_max_exceed.c"
    r0 = IMMEDIATE(1);
#line 139 "sample/tail_call_max_exceed.c"
    return r0;
#line 136 "sample/tail_call_max_exceed.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sample_test_callee4_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     14,
     "helper_id_14",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
};

static GUID sample_test_callee4_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sample_test_callee4_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sample_test_callee4_maps[] = {
    0,
};

#pragma code_seg(push, "sampl~32")
static uint64_t
sample_test_callee4(void* context, const program_runtime_context_t* runtime_context)
#line 89 "sample/tail_call_max_exceed.c"
{
#line 89 "sample/tail_call_max_exceed.c"
    // Prologue.
#line 89 "sample/tail_call_max_exceed.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 89 "sample/tail_call_max_exceed.c"
    register uint64_t r0 = 0;
#line 89 "sample/tail_call_max_exceed.c"
    register uint64_t r1 = 0;
#line 89 "sample/tail_call_max_exceed.c"
    register uint64_t r2 = 0;
#line 89 "sample/tail_call_max_exceed.c"
    register uint64_t r3 = 0;
#line 89 "sample/tail_call_max_exceed.c"
    register uint64_t r4 = 0;
#line 89 "sample/tail_call_max_exceed.c"
    register uint64_t r5 = 0;
#line 89 "sample/tail_call_max_exceed.c"
    register uint64_t r6 = 0;
#line 89 "sample/tail_call_max_exceed.c"
    register uint64_t r7 = 0;
#line 89 "sample/tail_call_max_exceed.c"
    register uint64_t r10 = 0;

#line 89 "sample/tail_call_max_exceed.c"
    r1 = (uintptr_t)context;
#line 89 "sample/tail_call_max_exceed.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 89 "sample/tail_call_max_exceed.c"
    r6 = r1;
#line 89 "sample/tail_call_max_exceed.c"
    r7 = IMMEDIATE(10);
#line 89 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-4));
#line 89 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1566844192);
#line 89 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-8));
#line 89 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)4404574498340937772;
#line 89 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
#line 89 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)6729544563593082971;
#line 89 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 89 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2339731488442490988;
#line 89 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 89 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099572;
#line 89 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 89 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2334956330884555075;
#line 89 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 89 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 89 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 89 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(46);
#line 89 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(4);
#line 89 "sample/tail_call_max_exceed.c"
    r4 = IMMEDIATE(5);
#line 89 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 89 "sample/tail_call_max_exceed.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[0].address);
#line 89 "sample/tail_call_max_exceed.c"
    r1 = r6;
#line 89 "sample/tail_call_max_exceed.c"
    r2 = POINTER(runtime_context->map_data[0].address);
#line 89 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(5);
#line 89 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 89 "sample/tail_call_max_exceed.c"
    if (r0 == 0) {
#line 89 "sample/tail_call_max_exceed.c"
        return 0;
#line 89 "sample/tail_call_max_exceed.c"
    }
#line 89 "sample/tail_call_max_exceed.c"
    if ((int64_t)r0 > IMMEDIATE(-1)) {
#line 89 "sample/tail_call_max_exceed.c"
        goto label_1;
#line 89 "sample/tail_call_max_exceed.c"
    }
#line 89 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-20));
#line 89 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1680154744);
#line 89 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-24));
#line 89 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7306085893296906528;
#line 89 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 89 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7234307576302018668;
#line 89 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 89 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099540;
#line 89 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 89 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 89 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 89 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(30);
#line 89 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(5);
#line 89 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
label_1:
#line 89 "sample/tail_call_max_exceed.c"
    r0 = IMMEDIATE(2);
#line 89 "sample/tail_call_max_exceed.c"
    return r0;
#line 89 "sample/tail_call_max_exceed.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sample_test_callee5_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     14,
     "helper_id_14",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
};

static GUID sample_test_callee5_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sample_test_callee5_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sample_test_callee5_maps[] = {
    0,
};

#pragma code_seg(push, "sampl~31")
static uint64_t
sample_test_callee5(void* context, const program_runtime_context_t* runtime_context)
#line 90 "sample/tail_call_max_exceed.c"
{
#line 90 "sample/tail_call_max_exceed.c"
    // Prologue.
#line 90 "sample/tail_call_max_exceed.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 90 "sample/tail_call_max_exceed.c"
    register uint64_t r0 = 0;
#line 90 "sample/tail_call_max_exceed.c"
    register uint64_t r1 = 0;
#line 90 "sample/tail_call_max_exceed.c"
    register uint64_t r2 = 0;
#line 90 "sample/tail_call_max_exceed.c"
    register uint64_t r3 = 0;
#line 90 "sample/tail_call_max_exceed.c"
    register uint64_t r4 = 0;
#line 90 "sample/tail_call_max_exceed.c"
    register uint64_t r5 = 0;
#line 90 "sample/tail_call_max_exceed.c"
    register uint64_t r6 = 0;
#line 90 "sample/tail_call_max_exceed.c"
    register uint64_t r7 = 0;
#line 90 "sample/tail_call_max_exceed.c"
    register uint64_t r10 = 0;

#line 90 "sample/tail_call_max_exceed.c"
    r1 = (uintptr_t)context;
#line 90 "sample/tail_call_max_exceed.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 90 "sample/tail_call_max_exceed.c"
    r6 = r1;
#line 90 "sample/tail_call_max_exceed.c"
    r7 = IMMEDIATE(10);
#line 90 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-4));
#line 90 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1566844192);
#line 90 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-8));
#line 90 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)4404574498340937772;
#line 90 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
#line 90 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)6729544563593082971;
#line 90 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 90 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2339731488442490988;
#line 90 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 90 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099572;
#line 90 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 90 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2334956330884555075;
#line 90 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 90 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 90 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 90 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(46);
#line 90 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(5);
#line 90 "sample/tail_call_max_exceed.c"
    r4 = IMMEDIATE(6);
#line 90 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 90 "sample/tail_call_max_exceed.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[0].address);
#line 90 "sample/tail_call_max_exceed.c"
    r1 = r6;
#line 90 "sample/tail_call_max_exceed.c"
    r2 = POINTER(runtime_context->map_data[0].address);
#line 90 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(6);
#line 90 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 90 "sample/tail_call_max_exceed.c"
    if (r0 == 0) {
#line 90 "sample/tail_call_max_exceed.c"
        return 0;
#line 90 "sample/tail_call_max_exceed.c"
    }
#line 90 "sample/tail_call_max_exceed.c"
    if ((int64_t)r0 > IMMEDIATE(-1)) {
#line 90 "sample/tail_call_max_exceed.c"
        goto label_1;
#line 90 "sample/tail_call_max_exceed.c"
    }
#line 90 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-20));
#line 90 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1680154744);
#line 90 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-24));
#line 90 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7306085893296906528;
#line 90 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 90 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7234307576302018668;
#line 90 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 90 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099540;
#line 90 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 90 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 90 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 90 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(30);
#line 90 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(6);
#line 90 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
label_1:
#line 90 "sample/tail_call_max_exceed.c"
    r0 = IMMEDIATE(2);
#line 90 "sample/tail_call_max_exceed.c"
    return r0;
#line 90 "sample/tail_call_max_exceed.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sample_test_callee6_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     14,
     "helper_id_14",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
};

static GUID sample_test_callee6_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sample_test_callee6_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sample_test_callee6_maps[] = {
    0,
};

#pragma code_seg(push, "sampl~30")
static uint64_t
sample_test_callee6(void* context, const program_runtime_context_t* runtime_context)
#line 91 "sample/tail_call_max_exceed.c"
{
#line 91 "sample/tail_call_max_exceed.c"
    // Prologue.
#line 91 "sample/tail_call_max_exceed.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 91 "sample/tail_call_max_exceed.c"
    register uint64_t r0 = 0;
#line 91 "sample/tail_call_max_exceed.c"
    register uint64_t r1 = 0;
#line 91 "sample/tail_call_max_exceed.c"
    register uint64_t r2 = 0;
#line 91 "sample/tail_call_max_exceed.c"
    register uint64_t r3 = 0;
#line 91 "sample/tail_call_max_exceed.c"
    register uint64_t r4 = 0;
#line 91 "sample/tail_call_max_exceed.c"
    register uint64_t r5 = 0;
#line 91 "sample/tail_call_max_exceed.c"
    register uint64_t r6 = 0;
#line 91 "sample/tail_call_max_exceed.c"
    register uint64_t r7 = 0;
#line 91 "sample/tail_call_max_exceed.c"
    register uint64_t r10 = 0;

#line 91 "sample/tail_call_max_exceed.c"
    r1 = (uintptr_t)context;
#line 91 "sample/tail_call_max_exceed.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 91 "sample/tail_call_max_exceed.c"
    r6 = r1;
#line 91 "sample/tail_call_max_exceed.c"
    r7 = IMMEDIATE(10);
#line 91 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-4));
#line 91 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1566844192);
#line 91 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-8));
#line 91 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)4404574498340937772;
#line 91 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
#line 91 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)6729544563593082971;
#line 91 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 91 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2339731488442490988;
#line 91 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 91 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099572;
#line 91 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 91 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2334956330884555075;
#line 91 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 91 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 91 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 91 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(46);
#line 91 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(6);
#line 91 "sample/tail_call_max_exceed.c"
    r4 = IMMEDIATE(7);
#line 91 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 91 "sample/tail_call_max_exceed.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[0].address);
#line 91 "sample/tail_call_max_exceed.c"
    r1 = r6;
#line 91 "sample/tail_call_max_exceed.c"
    r2 = POINTER(runtime_context->map_data[0].address);
#line 91 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(7);
#line 91 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 91 "sample/tail_call_max_exceed.c"
    if (r0 == 0) {
#line 91 "sample/tail_call_max_exceed.c"
        return 0;
#line 91 "sample/tail_call_max_exceed.c"
    }
#line 91 "sample/tail_call_max_exceed.c"
    if ((int64_t)r0 > IMMEDIATE(-1)) {
#line 91 "sample/tail_call_max_exceed.c"
        goto label_1;
#line 91 "sample/tail_call_max_exceed.c"
    }
#line 91 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-20));
#line 91 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1680154744);
#line 91 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-24));
#line 91 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7306085893296906528;
#line 91 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 91 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7234307576302018668;
#line 91 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 91 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099540;
#line 91 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 91 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 91 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 91 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(30);
#line 91 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(7);
#line 91 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
label_1:
#line 91 "sample/tail_call_max_exceed.c"
    r0 = IMMEDIATE(2);
#line 91 "sample/tail_call_max_exceed.c"
    return r0;
#line 91 "sample/tail_call_max_exceed.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sample_test_callee7_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     14,
     "helper_id_14",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
};

static GUID sample_test_callee7_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sample_test_callee7_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sample_test_callee7_maps[] = {
    0,
};

#pragma code_seg(push, "sampl~29")
static uint64_t
sample_test_callee7(void* context, const program_runtime_context_t* runtime_context)
#line 92 "sample/tail_call_max_exceed.c"
{
#line 92 "sample/tail_call_max_exceed.c"
    // Prologue.
#line 92 "sample/tail_call_max_exceed.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 92 "sample/tail_call_max_exceed.c"
    register uint64_t r0 = 0;
#line 92 "sample/tail_call_max_exceed.c"
    register uint64_t r1 = 0;
#line 92 "sample/tail_call_max_exceed.c"
    register uint64_t r2 = 0;
#line 92 "sample/tail_call_max_exceed.c"
    register uint64_t r3 = 0;
#line 92 "sample/tail_call_max_exceed.c"
    register uint64_t r4 = 0;
#line 92 "sample/tail_call_max_exceed.c"
    register uint64_t r5 = 0;
#line 92 "sample/tail_call_max_exceed.c"
    register uint64_t r6 = 0;
#line 92 "sample/tail_call_max_exceed.c"
    register uint64_t r7 = 0;
#line 92 "sample/tail_call_max_exceed.c"
    register uint64_t r10 = 0;

#line 92 "sample/tail_call_max_exceed.c"
    r1 = (uintptr_t)context;
#line 92 "sample/tail_call_max_exceed.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 92 "sample/tail_call_max_exceed.c"
    r6 = r1;
#line 92 "sample/tail_call_max_exceed.c"
    r7 = IMMEDIATE(10);
#line 92 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-4));
#line 92 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1566844192);
#line 92 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-8));
#line 92 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)4404574498340937772;
#line 92 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
#line 92 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)6729544563593082971;
#line 92 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 92 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2339731488442490988;
#line 92 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 92 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099572;
#line 92 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 92 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2334956330884555075;
#line 92 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 92 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 92 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 92 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(46);
#line 92 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(7);
#line 92 "sample/tail_call_max_exceed.c"
    r4 = IMMEDIATE(8);
#line 92 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 92 "sample/tail_call_max_exceed.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[0].address);
#line 92 "sample/tail_call_max_exceed.c"
    r1 = r6;
#line 92 "sample/tail_call_max_exceed.c"
    r2 = POINTER(runtime_context->map_data[0].address);
#line 92 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(8);
#line 92 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 92 "sample/tail_call_max_exceed.c"
    if (r0 == 0) {
#line 92 "sample/tail_call_max_exceed.c"
        return 0;
#line 92 "sample/tail_call_max_exceed.c"
    }
#line 92 "sample/tail_call_max_exceed.c"
    if ((int64_t)r0 > IMMEDIATE(-1)) {
#line 92 "sample/tail_call_max_exceed.c"
        goto label_1;
#line 92 "sample/tail_call_max_exceed.c"
    }
#line 92 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-20));
#line 92 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1680154744);
#line 92 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-24));
#line 92 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7306085893296906528;
#line 92 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 92 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7234307576302018668;
#line 92 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 92 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099540;
#line 92 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 92 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 92 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 92 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(30);
#line 92 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(8);
#line 92 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
label_1:
#line 92 "sample/tail_call_max_exceed.c"
    r0 = IMMEDIATE(2);
#line 92 "sample/tail_call_max_exceed.c"
    return r0;
#line 92 "sample/tail_call_max_exceed.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sample_test_callee8_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     14,
     "helper_id_14",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
};

static GUID sample_test_callee8_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sample_test_callee8_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sample_test_callee8_maps[] = {
    0,
};

#pragma code_seg(push, "sampl~28")
static uint64_t
sample_test_callee8(void* context, const program_runtime_context_t* runtime_context)
#line 93 "sample/tail_call_max_exceed.c"
{
#line 93 "sample/tail_call_max_exceed.c"
    // Prologue.
#line 93 "sample/tail_call_max_exceed.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 93 "sample/tail_call_max_exceed.c"
    register uint64_t r0 = 0;
#line 93 "sample/tail_call_max_exceed.c"
    register uint64_t r1 = 0;
#line 93 "sample/tail_call_max_exceed.c"
    register uint64_t r2 = 0;
#line 93 "sample/tail_call_max_exceed.c"
    register uint64_t r3 = 0;
#line 93 "sample/tail_call_max_exceed.c"
    register uint64_t r4 = 0;
#line 93 "sample/tail_call_max_exceed.c"
    register uint64_t r5 = 0;
#line 93 "sample/tail_call_max_exceed.c"
    register uint64_t r6 = 0;
#line 93 "sample/tail_call_max_exceed.c"
    register uint64_t r7 = 0;
#line 93 "sample/tail_call_max_exceed.c"
    register uint64_t r10 = 0;

#line 93 "sample/tail_call_max_exceed.c"
    r1 = (uintptr_t)context;
#line 93 "sample/tail_call_max_exceed.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 93 "sample/tail_call_max_exceed.c"
    r6 = r1;
#line 93 "sample/tail_call_max_exceed.c"
    r7 = IMMEDIATE(10);
#line 93 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-4));
#line 93 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1566844192);
#line 93 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-8));
#line 93 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)4404574498340937772;
#line 93 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
#line 93 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)6729544563593082971;
#line 93 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 93 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2339731488442490988;
#line 93 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 93 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099572;
#line 93 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 93 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2334956330884555075;
#line 93 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 93 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 93 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 93 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(46);
#line 93 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(8);
#line 93 "sample/tail_call_max_exceed.c"
    r4 = IMMEDIATE(9);
#line 93 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 93 "sample/tail_call_max_exceed.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[0].address);
#line 93 "sample/tail_call_max_exceed.c"
    r1 = r6;
#line 93 "sample/tail_call_max_exceed.c"
    r2 = POINTER(runtime_context->map_data[0].address);
#line 93 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(9);
#line 93 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 93 "sample/tail_call_max_exceed.c"
    if (r0 == 0) {
#line 93 "sample/tail_call_max_exceed.c"
        return 0;
#line 93 "sample/tail_call_max_exceed.c"
    }
#line 93 "sample/tail_call_max_exceed.c"
    if ((int64_t)r0 > IMMEDIATE(-1)) {
#line 93 "sample/tail_call_max_exceed.c"
        goto label_1;
#line 93 "sample/tail_call_max_exceed.c"
    }
#line 93 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-20));
#line 93 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1680154744);
#line 93 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-24));
#line 93 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7306085893296906528;
#line 93 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 93 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7234307576302018668;
#line 93 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 93 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099540;
#line 93 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 93 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 93 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 93 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(30);
#line 93 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(9);
#line 93 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
label_1:
#line 93 "sample/tail_call_max_exceed.c"
    r0 = IMMEDIATE(2);
#line 93 "sample/tail_call_max_exceed.c"
    return r0;
#line 93 "sample/tail_call_max_exceed.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sample_test_callee9_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     14,
     "helper_id_14",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
};

static GUID sample_test_callee9_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sample_test_callee9_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sample_test_callee9_maps[] = {
    0,
};

#pragma code_seg(push, "sampl~27")
static uint64_t
sample_test_callee9(void* context, const program_runtime_context_t* runtime_context)
#line 94 "sample/tail_call_max_exceed.c"
{
#line 94 "sample/tail_call_max_exceed.c"
    // Prologue.
#line 94 "sample/tail_call_max_exceed.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 94 "sample/tail_call_max_exceed.c"
    register uint64_t r0 = 0;
#line 94 "sample/tail_call_max_exceed.c"
    register uint64_t r1 = 0;
#line 94 "sample/tail_call_max_exceed.c"
    register uint64_t r2 = 0;
#line 94 "sample/tail_call_max_exceed.c"
    register uint64_t r3 = 0;
#line 94 "sample/tail_call_max_exceed.c"
    register uint64_t r4 = 0;
#line 94 "sample/tail_call_max_exceed.c"
    register uint64_t r5 = 0;
#line 94 "sample/tail_call_max_exceed.c"
    register uint64_t r6 = 0;
#line 94 "sample/tail_call_max_exceed.c"
    register uint64_t r7 = 0;
#line 94 "sample/tail_call_max_exceed.c"
    register uint64_t r10 = 0;

#line 94 "sample/tail_call_max_exceed.c"
    r1 = (uintptr_t)context;
#line 94 "sample/tail_call_max_exceed.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 94 "sample/tail_call_max_exceed.c"
    r6 = r1;
#line 94 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1566844192);
#line 94 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-8));
#line 94 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)4404574498340937772;
#line 94 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
#line 94 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)6729544563593082971;
#line 94 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 94 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2339731488442490988;
#line 94 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 94 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099572;
#line 94 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 94 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2334956330884555075;
#line 94 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 94 "sample/tail_call_max_exceed.c"
    r7 = IMMEDIATE(10);
#line 94 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-4));
#line 94 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 94 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 94 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(46);
#line 94 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(9);
#line 94 "sample/tail_call_max_exceed.c"
    r4 = IMMEDIATE(10);
#line 94 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 94 "sample/tail_call_max_exceed.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[0].address);
#line 94 "sample/tail_call_max_exceed.c"
    r1 = r6;
#line 94 "sample/tail_call_max_exceed.c"
    r2 = POINTER(runtime_context->map_data[0].address);
#line 94 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(10);
#line 94 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 94 "sample/tail_call_max_exceed.c"
    if (r0 == 0) {
#line 94 "sample/tail_call_max_exceed.c"
        return 0;
#line 94 "sample/tail_call_max_exceed.c"
    }
#line 94 "sample/tail_call_max_exceed.c"
    if ((int64_t)r0 > IMMEDIATE(-1)) {
#line 94 "sample/tail_call_max_exceed.c"
        goto label_1;
#line 94 "sample/tail_call_max_exceed.c"
    }
#line 94 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(1680154744);
#line 94 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-24));
#line 94 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7306085893296906528;
#line 94 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 94 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7234307576302018668;
#line 94 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 94 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7809632219746099540;
#line 94 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
#line 94 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r7, OFFSET(-20));
#line 94 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 94 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-48);
#line 94 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(30);
#line 94 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(10);
#line 94 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
label_1:
#line 94 "sample/tail_call_max_exceed.c"
    r0 = IMMEDIATE(2);
#line 94 "sample/tail_call_max_exceed.c"
    return r0;
#line 94 "sample/tail_call_max_exceed.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t sample_test_caller_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     12,
     "helper_id_12",
    },
    {
     {1, 40, 40}, // Version header.
     5,
     "helper_id_5",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
};

static GUID sample_test_caller_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID sample_test_caller_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t sample_test_caller_maps[] = {
    0,
};

#pragma code_seg(push, "sample~1")
static uint64_t
sample_test_caller(void* context, const program_runtime_context_t* runtime_context)
#line 124 "sample/tail_call_max_exceed.c"
{
#line 124 "sample/tail_call_max_exceed.c"
    // Prologue.
#line 124 "sample/tail_call_max_exceed.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 124 "sample/tail_call_max_exceed.c"
    register uint64_t r0 = 0;
#line 124 "sample/tail_call_max_exceed.c"
    register uint64_t r1 = 0;
#line 124 "sample/tail_call_max_exceed.c"
    register uint64_t r2 = 0;
#line 124 "sample/tail_call_max_exceed.c"
    register uint64_t r3 = 0;
#line 124 "sample/tail_call_max_exceed.c"
    register uint64_t r4 = 0;
#line 124 "sample/tail_call_max_exceed.c"
    register uint64_t r5 = 0;
#line 124 "sample/tail_call_max_exceed.c"
    register uint64_t r6 = 0;
#line 124 "sample/tail_call_max_exceed.c"
    register uint64_t r7 = 0;
#line 124 "sample/tail_call_max_exceed.c"
    register uint64_t r10 = 0;

#line 124 "sample/tail_call_max_exceed.c"
    r1 = (uintptr_t)context;
#line 124 "sample/tail_call_max_exceed.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 124 "sample/tail_call_max_exceed.c"
    r6 = r1;
#line 124 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2865818629860449;
#line 126 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-8));
#line 126 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7142828208871972980;
#line 126 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
#line 126 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)8241996693436527205;
#line 126 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 126 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7812726533012091749;
#line 126 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 126 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)8385532547604242803;
#line 126 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 126 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 126 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-40);
#line 126 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(40);
#line 126 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 126 "sample/tail_call_max_exceed.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[0].address);
#line 126 "sample/tail_call_max_exceed.c"
    r7 = IMMEDIATE(0);
#line 127 "sample/tail_call_max_exceed.c"
    r1 = r6;
#line 127 "sample/tail_call_max_exceed.c"
    r2 = POINTER(runtime_context->map_data[0].address);
#line 127 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(0);
#line 127 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 127 "sample/tail_call_max_exceed.c"
    if (r0 == 0) {
#line 127 "sample/tail_call_max_exceed.c"
        return 0;
#line 127 "sample/tail_call_max_exceed.c"
    }
#line 127 "sample/tail_call_max_exceed.c"
    if ((int64_t)r0 > IMMEDIATE(-1)) {
#line 127 "sample/tail_call_max_exceed.c"
        goto label_1;
#line 127 "sample/tail_call_max_exceed.c"
    }
#line 127 "sample/tail_call_max_exceed.c"
    r1 = IMMEDIATE(2660);
#line 128 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-16));
#line 128 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)2675270555530062112;
#line 128 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
#line 128 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)7812726531954600289;
#line 128 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-32));
#line 128 "sample/tail_call_max_exceed.c"
    r1 = (uint64_t)8367798494427701574;
#line 128 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
#line 128 "sample/tail_call_max_exceed.c"
    WRITE_ONCE_8(r10, (uint8_t)r7, OFFSET(-14));
#line 128 "sample/tail_call_max_exceed.c"
    r1 = r10;
#line 128 "sample/tail_call_max_exceed.c"
    r1 += IMMEDIATE(-40);
#line 128 "sample/tail_call_max_exceed.c"
    r2 = IMMEDIATE(27);
#line 128 "sample/tail_call_max_exceed.c"
    r3 = IMMEDIATE(0);
#line 128 "sample/tail_call_max_exceed.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
label_1:
#line 131 "sample/tail_call_max_exceed.c"
    r0 = IMMEDIATE(2);
#line 131 "sample/tail_call_max_exceed.c"
    return r0;
#line 124 "sample/tail_call_max_exceed.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        {1, 154, 160}, // Version header.
        sample_test_callee0,
        "sampl~36",
        "sample_ext/0",
        "sample_test_callee0",
        sample_test_callee0_maps,
        1,
        sample_test_callee0_helpers,
        3,
        51,
        &sample_test_callee0_program_type_guid,
        &sample_test_callee0_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        sample_test_callee1,
        "sampl~35",
        "sample_ext/1",
        "sample_test_callee1",
        sample_test_callee1_maps,
        1,
        sample_test_callee1_helpers,
        3,
        51,
        &sample_test_callee1_program_type_guid,
        &sample_test_callee1_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        sample_test_callee10,
        "sampl~26",
        "sample_ext/10",
        "sample_test_callee10",
        sample_test_callee10_maps,
        1,
        sample_test_callee10_helpers,
        3,
        51,
        &sample_test_callee10_program_type_guid,
        &sample_test_callee10_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        sample_test_callee11,
        "sampl~25",
        "sample_ext/11",
        "sample_test_callee11",
        sample_test_callee11_maps,
        1,
        sample_test_callee11_helpers,
        3,
        51,
        &sample_test_callee11_program_type_guid,
        &sample_test_callee11_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        sample_test_callee12,
        "sampl~24",
        "sample_ext/12",
        "sample_test_callee12",
        sample_test_callee12_maps,
        1,
        sample_test_callee12_helpers,
        3,
        51,
        &sample_test_callee12_program_type_guid,
        &sample_test_callee12_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        sample_test_callee13,
        "sampl~23",
        "sample_ext/13",
        "sample_test_callee13",
        sample_test_callee13_maps,
        1,
        sample_test_callee13_helpers,
        3,
        51,
        &sample_test_callee13_program_type_guid,
        &sample_test_callee13_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        sample_test_callee14,
        "sampl~22",
        "sample_ext/14",
        "sample_test_callee14",
        sample_test_callee14_maps,
        1,
        sample_test_callee14_helpers,
        3,
        51,
        &sample_test_callee14_program_type_guid,
        &sample_test_callee14_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        sample_test_callee15,
        "sampl~21",
        "sample_ext/15",
        "sample_test_callee15",
        sample_test_callee15_maps,
        1,
        sample_test_callee15_helpers,
        3,
        51,
        &sample_test_callee15_program_type_guid,
        &sample_test_callee15_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        sample_test_callee16,
        "sampl~20",
        "sample_ext/16",
        "sample_test_callee16",
        sample_test_callee16_maps,
        1,
        sample_test_callee16_helpers,
        3,
        51,
        &sample_test_callee16_program_type_guid,
        &sample_test_callee16_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        sample_test_callee17,
        "sampl~19",
        "sample_ext/17",
        "sample_test_callee17",
        sample_test_callee17_maps,
        1,
        sample_test_callee17_helpers,
        3,
        51,
        &sample_test_callee17_program_type_guid,
        &sample_test_callee17_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        sample_test_callee18,
        "sampl~18",
        "sample_ext/18",
        "sample_test_callee18",
        sample_test_callee18_maps,
        1,
        sample_test_callee18_helpers,
        3,
        51,
        &sample_test_callee18_program_type_guid,
        &sample_test_callee18_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        sample_test_callee19,
        "sampl~17",
        "sample_ext/19",
        "sample_test_callee19",
        sample_test_callee19_maps,
        1,
        sample_test_callee19_helpers,
        3,
        51,
        &sample_test_callee19_program_type_guid,
        &sample_test_callee19_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        sample_test_callee2,
        "sampl~34",
        "sample_ext/2",
        "sample_test_callee2",
        sample_test_callee2_maps,
        1,
        sample_test_callee2_helpers,
        3,
        51,
        &sample_test_callee2_program_type_guid,
        &sample_test_callee2_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        sample_test_callee20,
        "sampl~16",
        "sample_ext/20",
        "sample_test_callee20",
        sample_test_callee20_maps,
        1,
        sample_test_callee20_helpers,
        3,
        51,
        &sample_test_callee20_program_type_guid,
        &sample_test_callee20_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        sample_test_callee21,
        "sampl~15",
        "sample_ext/21",
        "sample_test_callee21",
        sample_test_callee21_maps,
        1,
        sample_test_callee21_helpers,
        3,
        51,
        &sample_test_callee21_program_type_guid,
        &sample_test_callee21_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        sample_test_callee22,
        "sampl~14",
        "sample_ext/22",
        "sample_test_callee22",
        sample_test_callee22_maps,
        1,
        sample_test_callee22_helpers,
        3,
        51,
        &sample_test_callee22_program_type_guid,
        &sample_test_callee22_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        sample_test_callee23,
        "sampl~13",
        "sample_ext/23",
        "sample_test_callee23",
        sample_test_callee23_maps,
        1,
        sample_test_callee23_helpers,
        3,
        51,
        &sample_test_callee23_program_type_guid,
        &sample_test_callee23_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        sample_test_callee24,
        "sampl~12",
        "sample_ext/24",
        "sample_test_callee24",
        sample_test_callee24_maps,
        1,
        sample_test_callee24_helpers,
        3,
        51,
        &sample_test_callee24_program_type_guid,
        &sample_test_callee24_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        sample_test_callee25,
        "sampl~11",
        "sample_ext/25",
        "sample_test_callee25",
        sample_test_callee25_maps,
        1,
        sample_test_callee25_helpers,
        3,
        51,
        &sample_test_callee25_program_type_guid,
        &sample_test_callee25_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        sample_test_callee26,
        "sampl~10",
        "sample_ext/26",
        "sample_test_callee26",
        sample_test_callee26_maps,
        1,
        sample_test_callee26_helpers,
        3,
        51,
        &sample_test_callee26_program_type_guid,
        &sample_test_callee26_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        sample_test_callee27,
        "sample~9",
        "sample_ext/27",
        "sample_test_callee27",
        sample_test_callee27_maps,
        1,
        sample_test_callee27_helpers,
        3,
        51,
        &sample_test_callee27_program_type_guid,
        &sample_test_callee27_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        sample_test_callee28,
        "sample~8",
        "sample_ext/28",
        "sample_test_callee28",
        sample_test_callee28_maps,
        1,
        sample_test_callee28_helpers,
        3,
        51,
        &sample_test_callee28_program_type_guid,
        &sample_test_callee28_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        sample_test_callee29,
        "sample~7",
        "sample_ext/29",
        "sample_test_callee29",
        sample_test_callee29_maps,
        1,
        sample_test_callee29_helpers,
        3,
        51,
        &sample_test_callee29_program_type_guid,
        &sample_test_callee29_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        sample_test_callee3,
        "sampl~33",
        "sample_ext/3",
        "sample_test_callee3",
        sample_test_callee3_maps,
        1,
        sample_test_callee3_helpers,
        3,
        51,
        &sample_test_callee3_program_type_guid,
        &sample_test_callee3_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        sample_test_callee30,
        "sample~6",
        "sample_ext/30",
        "sample_test_callee30",
        sample_test_callee30_maps,
        1,
        sample_test_callee30_helpers,
        3,
        51,
        &sample_test_callee30_program_type_guid,
        &sample_test_callee30_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        sample_test_callee31,
        "sample~5",
        "sample_ext/31",
        "sample_test_callee31",
        sample_test_callee31_maps,
        1,
        sample_test_callee31_helpers,
        3,
        51,
        &sample_test_callee31_program_type_guid,
        &sample_test_callee31_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        sample_test_callee32,
        "sample~4",
        "sample_ext/32",
        "sample_test_callee32",
        sample_test_callee32_maps,
        1,
        sample_test_callee32_helpers,
        3,
        51,
        &sample_test_callee32_program_type_guid,
        &sample_test_callee32_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        sample_test_callee33,
        "sample~3",
        "sample_ext/33",
        "sample_test_callee33",
        sample_test_callee33_maps,
        1,
        sample_test_callee33_helpers,
        3,
        51,
        &sample_test_callee33_program_type_guid,
        &sample_test_callee33_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        sample_test_callee34,
        "sample~2",
        "sample_ext/34",
        "sample_test_callee34",
        NULL,
        0,
        sample_test_callee34_helpers,
        1,
        23,
        &sample_test_callee34_program_type_guid,
        &sample_test_callee34_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        sample_test_callee4,
        "sampl~32",
        "sample_ext/4",
        "sample_test_callee4",
        sample_test_callee4_maps,
        1,
        sample_test_callee4_helpers,
        3,
        51,
        &sample_test_callee4_program_type_guid,
        &sample_test_callee4_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        sample_test_callee5,
        "sampl~31",
        "sample_ext/5",
        "sample_test_callee5",
        sample_test_callee5_maps,
        1,
        sample_test_callee5_helpers,
        3,
        51,
        &sample_test_callee5_program_type_guid,
        &sample_test_callee5_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        sample_test_callee6,
        "sampl~30",
        "sample_ext/6",
        "sample_test_callee6",
        sample_test_callee6_maps,
        1,
        sample_test_callee6_helpers,
        3,
        51,
        &sample_test_callee6_program_type_guid,
        &sample_test_callee6_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        sample_test_callee7,
        "sampl~29",
        "sample_ext/7",
        "sample_test_callee7",
        sample_test_callee7_maps,
        1,
        sample_test_callee7_helpers,
        3,
        51,
        &sample_test_callee7_program_type_guid,
        &sample_test_callee7_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        sample_test_callee8,
        "sampl~28",
        "sample_ext/8",
        "sample_test_callee8",
        sample_test_callee8_maps,
        1,
        sample_test_callee8_helpers,
        3,
        51,
        &sample_test_callee8_program_type_guid,
        &sample_test_callee8_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        sample_test_callee9,
        "sampl~27",
        "sample_ext/9",
        "sample_test_callee9",
        sample_test_callee9_maps,
        1,
        sample_test_callee9_helpers,
        3,
        51,
        &sample_test_callee9_program_type_guid,
        &sample_test_callee9_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        sample_test_caller,
        "sample~1",
        "sample_ext",
        "sample_test_caller",
        sample_test_caller_maps,
        1,
        sample_test_caller_helpers,
        3,
        46,
        &sample_test_caller_program_type_guid,
        &sample_test_caller_attach_type_guid,
    },
};
#pragma data_seg(pop)

static void
_get_programs(_Outptr_result_buffer_(*count) program_entry_t** programs, _Out_ size_t* count)
{
    *programs = _programs;
    *count = 36;
}

static void
_get_version(_Out_ bpf2c_version_t* version)
{
    version->major = EBPF_VERSION_MAJOR;
    version->minor = EBPF_VERSION_MINOR;
    version->revision = EBPF_VERSION_REVISION;
}

#pragma data_seg(push, "map_initial_values")
// clang-format off
static const char* _sample_tail_call_map_initial_string_table[] = {
    "sample_test_callee0",
    "sample_test_callee1",
    "sample_test_callee2",
    "sample_test_callee3",
    "sample_test_callee4",
    "sample_test_callee5",
    "sample_test_callee6",
    "sample_test_callee7",
    "sample_test_callee8",
    "sample_test_callee9",
    "sample_test_callee10",
    "sample_test_callee11",
    "sample_test_callee12",
    "sample_test_callee13",
    "sample_test_callee14",
    "sample_test_callee15",
    "sample_test_callee16",
    "sample_test_callee17",
    "sample_test_callee18",
    "sample_test_callee19",
    "sample_test_callee20",
    "sample_test_callee21",
    "sample_test_callee22",
    "sample_test_callee23",
    "sample_test_callee24",
    "sample_test_callee25",
    "sample_test_callee26",
    "sample_test_callee27",
    "sample_test_callee28",
    "sample_test_callee29",
    "sample_test_callee30",
    "sample_test_callee31",
    "sample_test_callee32",
    "sample_test_callee33",
    "sample_test_callee34",
};
// clang-format on

static map_initial_values_t _map_initial_values_array[] = {
    {
        .header = {1, 48, 48},
        .name = "sample_tail_call_map",
        .count = 35,
        .values = _sample_tail_call_map_initial_string_table,
    },
};
#pragma data_seg(pop)

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = _map_initial_values_array;
    *count = 1;
}

metadata_table_t tail_call_max_exceed_metadata_table = {
    sizeof(metadata_table_t),
    _get_programs,
    _get_maps,
    _get_hash,
    _get_version,
    _get_map_initial_values,
    _get_global_variable_sections,
};
