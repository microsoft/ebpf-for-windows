// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from test_utility_helpers.o

#define NO_CRT
#include "bpf2c.h"

#include <guiddef.h>
#include <wdm.h>
#include <wsk.h>

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
RTL_QUERY_REGISTRY_ROUTINE static _bpf2c_query_registry_routine;

#define metadata_table test_utility_helpers##_metadata_table

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
     &metadata_table}};

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

#pragma warning(push)
#pragma warning( \
    disable : 6387) // Param 3 does not adhere to the specification for the function 'NmrClientAttachProvider'
    // As per MSDN, client dispatch can be NULL, but SAL does not allow it.
    // https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/netioddk/nf-netioddk-nmrclientattachprovider
    status = NmrClientAttachProvider(
        nmr_binding_handle, client_context, NULL, &provider_binding_context, &provider_dispatch_table);
    if (status != STATUS_SUCCESS) {
        goto Done;
    }
#pragma warning(pop)
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
#pragma data_seg(push, "maps")
static map_entry_t _maps[] = {
    {NULL,
     {
         BPF_MAP_TYPE_ARRAY, // Type of map.
         4,                  // Size in bytes of a map key.
         40,                 // Size in bytes of a map value.
         2,                  // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         PIN_NONE,           // Pinning type for the map.
         13,                 // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "utility_map"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 1;
}

static helper_function_entry_t test_utility_helpers_helpers[] = {
    {NULL, 6, "helper_id_6"},
    {NULL, 7, "helper_id_7"},
    {NULL, 9, "helper_id_9"},
    {NULL, 8, "helper_id_8"},
    {NULL, 19, "helper_id_19"},
    {NULL, 2, "helper_id_2"},
};

static GUID test_utility_helpers_program_type_guid = {
    0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID test_utility_helpers_attach_type_guid = {
    0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
static uint16_t test_utility_helpers_maps[] = {
    0,
};

#pragma code_seg(push, "xdp")
static uint64_t
test_utility_helpers(void* context)
#line 32 "sample/test_utility_helpers.c"
{
#line 32 "sample/test_utility_helpers.c"
    // Prologue
#line 32 "sample/test_utility_helpers.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 32 "sample/test_utility_helpers.c"
    register uint64_t r0 = 0;
#line 32 "sample/test_utility_helpers.c"
    register uint64_t r1 = 0;
#line 32 "sample/test_utility_helpers.c"
    register uint64_t r2 = 0;
#line 32 "sample/test_utility_helpers.c"
    register uint64_t r3 = 0;
#line 32 "sample/test_utility_helpers.c"
    register uint64_t r4 = 0;
#line 32 "sample/test_utility_helpers.c"
    register uint64_t r5 = 0;
#line 32 "sample/test_utility_helpers.c"
    register uint64_t r6 = 0;
#line 32 "sample/test_utility_helpers.c"
    register uint64_t r10 = 0;

#line 32 "sample/test_utility_helpers.c"
    r1 = (uintptr_t)context;
#line 32 "sample/test_utility_helpers.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_LDDW pc=0 dst=r1 src=r0 offset=0 imm=0
#line 32 "sample/test_utility_helpers.c"
    r1 = (uint64_t)4294967296;
    // EBPF_OP_STXDW pc=2 dst=r10 src=r1 offset=-8 imm=0
#line 12 "sample/./sample_common_routines.h"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint64_t)r1;
    // EBPF_OP_MOV64_IMM pc=3 dst=r1 src=r0 offset=0 imm=0
#line 12 "sample/./sample_common_routines.h"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=4 dst=r10 src=r1 offset=-24 imm=0
#line 13 "sample/./sample_common_routines.h"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=5 dst=r10 src=r1 offset=-32 imm=0
#line 13 "sample/./sample_common_routines.h"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=6 dst=r10 src=r1 offset=-40 imm=0
#line 13 "sample/./sample_common_routines.h"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=7 dst=r10 src=r1 offset=-48 imm=0
#line 13 "sample/./sample_common_routines.h"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_CALL pc=8 dst=r0 src=r0 offset=0 imm=6
#line 16 "sample/./sample_common_routines.h"
    r0 = test_utility_helpers_helpers[0].address
#line 16 "sample/./sample_common_routines.h"
         (r1, r2, r3, r4, r5);
#line 16 "sample/./sample_common_routines.h"
    if ((test_utility_helpers_helpers[0].tail_call) && (r0 == 0))
#line 16 "sample/./sample_common_routines.h"
        return 0;
        // EBPF_OP_STXW pc=9 dst=r10 src=r0 offset=-48 imm=0
#line 16 "sample/./sample_common_routines.h"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint32_t)r0;
    // EBPF_OP_CALL pc=10 dst=r0 src=r0 offset=0 imm=7
#line 24 "sample/./sample_common_routines.h"
    r0 = test_utility_helpers_helpers[1].address
#line 24 "sample/./sample_common_routines.h"
         (r1, r2, r3, r4, r5);
#line 24 "sample/./sample_common_routines.h"
    if ((test_utility_helpers_helpers[1].tail_call) && (r0 == 0))
#line 24 "sample/./sample_common_routines.h"
        return 0;
        // EBPF_OP_STXDW pc=11 dst=r10 src=r0 offset=-32 imm=0
#line 24 "sample/./sample_common_routines.h"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r0;
    // EBPF_OP_CALL pc=12 dst=r0 src=r0 offset=0 imm=9
#line 27 "sample/./sample_common_routines.h"
    r0 = test_utility_helpers_helpers[2].address
#line 27 "sample/./sample_common_routines.h"
         (r1, r2, r3, r4, r5);
#line 27 "sample/./sample_common_routines.h"
    if ((test_utility_helpers_helpers[2].tail_call) && (r0 == 0))
#line 27 "sample/./sample_common_routines.h"
        return 0;
        // EBPF_OP_STXDW pc=13 dst=r10 src=r0 offset=-40 imm=0
#line 27 "sample/./sample_common_routines.h"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r0;
    // EBPF_OP_CALL pc=14 dst=r0 src=r0 offset=0 imm=8
#line 30 "sample/./sample_common_routines.h"
    r0 = test_utility_helpers_helpers[3].address
#line 30 "sample/./sample_common_routines.h"
         (r1, r2, r3, r4, r5);
#line 30 "sample/./sample_common_routines.h"
    if ((test_utility_helpers_helpers[3].tail_call) && (r0 == 0))
#line 30 "sample/./sample_common_routines.h"
        return 0;
        // EBPF_OP_STXW pc=15 dst=r10 src=r0 offset=-24 imm=0
#line 30 "sample/./sample_common_routines.h"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r0;
    // EBPF_OP_CALL pc=16 dst=r0 src=r0 offset=0 imm=19
#line 33 "sample/./sample_common_routines.h"
    r0 = test_utility_helpers_helpers[4].address
#line 33 "sample/./sample_common_routines.h"
         (r1, r2, r3, r4, r5);
#line 33 "sample/./sample_common_routines.h"
    if ((test_utility_helpers_helpers[4].tail_call) && (r0 == 0))
#line 33 "sample/./sample_common_routines.h"
        return 0;
        // EBPF_OP_STXDW pc=17 dst=r10 src=r0 offset=-16 imm=0
#line 33 "sample/./sample_common_routines.h"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r0;
    // EBPF_OP_MOV64_REG pc=18 dst=r2 src=r10 offset=0 imm=0
#line 33 "sample/./sample_common_routines.h"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=19 dst=r2 src=r0 offset=0 imm=-8
#line 33 "sample/./sample_common_routines.h"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_REG pc=20 dst=r6 src=r10 offset=0 imm=0
#line 33 "sample/./sample_common_routines.h"
    r6 = r10;
    // EBPF_OP_ADD64_IMM pc=21 dst=r6 src=r0 offset=0 imm=-48
#line 33 "sample/./sample_common_routines.h"
    r6 += IMMEDIATE(-48);
    // EBPF_OP_LDDW pc=22 dst=r1 src=r0 offset=0 imm=0
#line 36 "sample/./sample_common_routines.h"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_REG pc=24 dst=r3 src=r6 offset=0 imm=0
#line 36 "sample/./sample_common_routines.h"
    r3 = r6;
    // EBPF_OP_MOV64_IMM pc=25 dst=r4 src=r0 offset=0 imm=0
#line 36 "sample/./sample_common_routines.h"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=26 dst=r0 src=r0 offset=0 imm=2
#line 36 "sample/./sample_common_routines.h"
    r0 = test_utility_helpers_helpers[5].address
#line 36 "sample/./sample_common_routines.h"
         (r1, r2, r3, r4, r5);
#line 36 "sample/./sample_common_routines.h"
    if ((test_utility_helpers_helpers[5].tail_call) && (r0 == 0))
#line 36 "sample/./sample_common_routines.h"
        return 0;
        // EBPF_OP_CALL pc=27 dst=r0 src=r0 offset=0 imm=6
#line 39 "sample/./sample_common_routines.h"
    r0 = test_utility_helpers_helpers[0].address
#line 39 "sample/./sample_common_routines.h"
         (r1, r2, r3, r4, r5);
#line 39 "sample/./sample_common_routines.h"
    if ((test_utility_helpers_helpers[0].tail_call) && (r0 == 0))
#line 39 "sample/./sample_common_routines.h"
        return 0;
        // EBPF_OP_STXW pc=28 dst=r10 src=r0 offset=-48 imm=0
#line 39 "sample/./sample_common_routines.h"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint32_t)r0;
    // EBPF_OP_CALL pc=29 dst=r0 src=r0 offset=0 imm=9
#line 42 "sample/./sample_common_routines.h"
    r0 = test_utility_helpers_helpers[2].address
#line 42 "sample/./sample_common_routines.h"
         (r1, r2, r3, r4, r5);
#line 42 "sample/./sample_common_routines.h"
    if ((test_utility_helpers_helpers[2].tail_call) && (r0 == 0))
#line 42 "sample/./sample_common_routines.h"
        return 0;
        // EBPF_OP_STXDW pc=30 dst=r10 src=r0 offset=-40 imm=0
#line 42 "sample/./sample_common_routines.h"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r0;
    // EBPF_OP_CALL pc=31 dst=r0 src=r0 offset=0 imm=7
#line 45 "sample/./sample_common_routines.h"
    r0 = test_utility_helpers_helpers[1].address
#line 45 "sample/./sample_common_routines.h"
         (r1, r2, r3, r4, r5);
#line 45 "sample/./sample_common_routines.h"
    if ((test_utility_helpers_helpers[1].tail_call) && (r0 == 0))
#line 45 "sample/./sample_common_routines.h"
        return 0;
        // EBPF_OP_STXDW pc=32 dst=r10 src=r0 offset=-32 imm=0
#line 45 "sample/./sample_common_routines.h"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r0;
    // EBPF_OP_CALL pc=33 dst=r0 src=r0 offset=0 imm=19
#line 48 "sample/./sample_common_routines.h"
    r0 = test_utility_helpers_helpers[4].address
#line 48 "sample/./sample_common_routines.h"
         (r1, r2, r3, r4, r5);
#line 48 "sample/./sample_common_routines.h"
    if ((test_utility_helpers_helpers[4].tail_call) && (r0 == 0))
#line 48 "sample/./sample_common_routines.h"
        return 0;
        // EBPF_OP_STXDW pc=34 dst=r10 src=r0 offset=-16 imm=0
#line 48 "sample/./sample_common_routines.h"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r0;
    // EBPF_OP_MOV64_REG pc=35 dst=r2 src=r10 offset=0 imm=0
#line 51 "sample/./sample_common_routines.h"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=36 dst=r2 src=r0 offset=0 imm=-4
#line 51 "sample/./sample_common_routines.h"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=37 dst=r1 src=r0 offset=0 imm=0
#line 51 "sample/./sample_common_routines.h"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_REG pc=39 dst=r3 src=r6 offset=0 imm=0
#line 51 "sample/./sample_common_routines.h"
    r3 = r6;
    // EBPF_OP_MOV64_IMM pc=40 dst=r4 src=r0 offset=0 imm=0
#line 51 "sample/./sample_common_routines.h"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=41 dst=r0 src=r0 offset=0 imm=2
#line 51 "sample/./sample_common_routines.h"
    r0 = test_utility_helpers_helpers[5].address
#line 51 "sample/./sample_common_routines.h"
         (r1, r2, r3, r4, r5);
#line 51 "sample/./sample_common_routines.h"
    if ((test_utility_helpers_helpers[5].tail_call) && (r0 == 0))
#line 51 "sample/./sample_common_routines.h"
        return 0;
        // EBPF_OP_MOV64_IMM pc=42 dst=r0 src=r0 offset=0 imm=0
#line 34 "sample/test_utility_helpers.c"
    r0 = IMMEDIATE(0);
    // EBPF_OP_EXIT pc=43 dst=r0 src=r0 offset=0 imm=0
#line 34 "sample/test_utility_helpers.c"
    return r0;
#line 34 "sample/test_utility_helpers.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        test_utility_helpers,
        "xdp",
        "xdp",
        "test_utility_helpers",
        test_utility_helpers_maps,
        1,
        test_utility_helpers_helpers,
        6,
        44,
        &test_utility_helpers_program_type_guid,
        &test_utility_helpers_attach_type_guid,
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
    version->major = 0;
    version->minor = 10;
    version->revision = 0;
}

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = NULL;
    *count = 0;
}

metadata_table_t test_utility_helpers_metadata_table = {
    sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version, _get_map_initial_values};
