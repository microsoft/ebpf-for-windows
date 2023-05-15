// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from cgroup_count_connect6.o

#define NO_CRT
#include "bpf2c.h"

#include <guiddef.h>
#include <wdm.h>
#include <wsk.h>

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
RTL_QUERY_REGISTRY_ROUTINE static _bpf2c_query_registry_routine;

#define metadata_table cgroup_count_connect6##_metadata_table

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
         BPF_MAP_TYPE_HASH, // Type of map.
         2,                 // Size in bytes of a map key.
         8,                 // Size in bytes of a map value.
         1,                 // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         PIN_NONE,          // Pinning type for the map.
         0,                 // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "connect6_count_map"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 1;
}

static helper_function_entry_t count_tcp_connect6_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 2, "helper_id_2"},
};

static GUID count_tcp_connect6_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID count_tcp_connect6_attach_type_guid = {
    0xa82e37b2, 0xaee7, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static uint16_t count_tcp_connect6_maps[] = {
    0,
};

#pragma code_seg(push, "cgroup~1")
static uint64_t
count_tcp_connect6(void* context)
#line 27 "sample/cgroup_count_connect6.c"
{
#line 27 "sample/cgroup_count_connect6.c"
    // Prologue
#line 27 "sample/cgroup_count_connect6.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 27 "sample/cgroup_count_connect6.c"
    register uint64_t r0 = 0;
#line 27 "sample/cgroup_count_connect6.c"
    register uint64_t r1 = 0;
#line 27 "sample/cgroup_count_connect6.c"
    register uint64_t r2 = 0;
#line 27 "sample/cgroup_count_connect6.c"
    register uint64_t r3 = 0;
#line 27 "sample/cgroup_count_connect6.c"
    register uint64_t r4 = 0;
#line 27 "sample/cgroup_count_connect6.c"
    register uint64_t r5 = 0;
#line 27 "sample/cgroup_count_connect6.c"
    register uint64_t r6 = 0;
#line 27 "sample/cgroup_count_connect6.c"
    register uint64_t r10 = 0;

#line 27 "sample/cgroup_count_connect6.c"
    r1 = (uintptr_t)context;
#line 27 "sample/cgroup_count_connect6.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r6 src=r0 offset=0 imm=1
#line 27 "sample/cgroup_count_connect6.c"
    r6 = IMMEDIATE(1);
    // EBPF_OP_LDXW pc=1 dst=r2 src=r1 offset=44 imm=0
#line 30 "sample/cgroup_count_connect6.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(44));
    // EBPF_OP_JNE_IMM pc=2 dst=r2 src=r0 offset=27 imm=6
#line 30 "sample/cgroup_count_connect6.c"
    if (r2 != IMMEDIATE(6))
#line 30 "sample/cgroup_count_connect6.c"
        goto label_2;
    // EBPF_OP_LDXH pc=3 dst=r1 src=r1 offset=40 imm=0
#line 36 "sample/cgroup_count_connect6.c"
    r1 = *(uint16_t*)(uintptr_t)(r1 + OFFSET(40));
    // EBPF_OP_JNE_IMM pc=4 dst=r1 src=r0 offset=25 imm=7459
#line 36 "sample/cgroup_count_connect6.c"
    if (r1 != IMMEDIATE(7459))
#line 36 "sample/cgroup_count_connect6.c"
        goto label_2;
    // EBPF_OP_MOV64_IMM pc=5 dst=r6 src=r0 offset=0 imm=0
#line 36 "sample/cgroup_count_connect6.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=6 dst=r10 src=r6 offset=-16 imm=0
#line 43 "sample/cgroup_count_connect6.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r6;
    // EBPF_OP_MOV64_IMM pc=7 dst=r1 src=r0 offset=0 imm=8989
#line 43 "sample/cgroup_count_connect6.c"
    r1 = IMMEDIATE(8989);
    // EBPF_OP_STXH pc=8 dst=r10 src=r1 offset=-2 imm=0
#line 42 "sample/cgroup_count_connect6.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-2)) = (uint16_t)r1;
    // EBPF_OP_MOV64_REG pc=9 dst=r2 src=r10 offset=0 imm=0
#line 42 "sample/cgroup_count_connect6.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=10 dst=r2 src=r0 offset=0 imm=-2
#line 42 "sample/cgroup_count_connect6.c"
    r2 += IMMEDIATE(-2);
    // EBPF_OP_LDDW pc=11 dst=r1 src=r0 offset=0 imm=0
#line 44 "sample/cgroup_count_connect6.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=1
#line 44 "sample/cgroup_count_connect6.c"
    r0 = count_tcp_connect6_helpers[0].address
#line 44 "sample/cgroup_count_connect6.c"
         (r1, r2, r3, r4, r5);
#line 44 "sample/cgroup_count_connect6.c"
    if ((count_tcp_connect6_helpers[0].tail_call) && (r0 == 0))
#line 44 "sample/cgroup_count_connect6.c"
        return 0;
    // EBPF_OP_JNE_IMM pc=14 dst=r0 src=r0 offset=12 imm=0
#line 45 "sample/cgroup_count_connect6.c"
    if (r0 != IMMEDIATE(0))
#line 45 "sample/cgroup_count_connect6.c"
        goto label_1;
    // EBPF_OP_MOV64_IMM pc=15 dst=r1 src=r0 offset=0 imm=1
#line 45 "sample/cgroup_count_connect6.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXDW pc=16 dst=r10 src=r1 offset=-16 imm=0
#line 46 "sample/cgroup_count_connect6.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=17 dst=r2 src=r10 offset=0 imm=0
#line 46 "sample/cgroup_count_connect6.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=18 dst=r2 src=r0 offset=0 imm=-2
#line 46 "sample/cgroup_count_connect6.c"
    r2 += IMMEDIATE(-2);
    // EBPF_OP_MOV64_REG pc=19 dst=r3 src=r10 offset=0 imm=0
#line 46 "sample/cgroup_count_connect6.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=20 dst=r3 src=r0 offset=0 imm=-16
#line 46 "sample/cgroup_count_connect6.c"
    r3 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_IMM pc=21 dst=r6 src=r0 offset=0 imm=0
#line 46 "sample/cgroup_count_connect6.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=22 dst=r1 src=r0 offset=0 imm=0
#line 47 "sample/cgroup_count_connect6.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=24 dst=r4 src=r0 offset=0 imm=0
#line 47 "sample/cgroup_count_connect6.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=2
#line 47 "sample/cgroup_count_connect6.c"
    r0 = count_tcp_connect6_helpers[1].address
#line 47 "sample/cgroup_count_connect6.c"
         (r1, r2, r3, r4, r5);
#line 47 "sample/cgroup_count_connect6.c"
    if ((count_tcp_connect6_helpers[1].tail_call) && (r0 == 0))
#line 47 "sample/cgroup_count_connect6.c"
        return 0;
    // EBPF_OP_JA pc=26 dst=r0 src=r0 offset=3 imm=0
#line 47 "sample/cgroup_count_connect6.c"
    goto label_2;
label_1:
    // EBPF_OP_LDXDW pc=27 dst=r1 src=r0 offset=0 imm=0
#line 49 "sample/cgroup_count_connect6.c"
    r1 = *(uint64_t*)(uintptr_t)(r0 + OFFSET(0));
    // EBPF_OP_ADD64_IMM pc=28 dst=r1 src=r0 offset=0 imm=1
#line 49 "sample/cgroup_count_connect6.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXDW pc=29 dst=r0 src=r1 offset=0 imm=0
#line 49 "sample/cgroup_count_connect6.c"
    *(uint64_t*)(uintptr_t)(r0 + OFFSET(0)) = (uint64_t)r1;
label_2:
    // EBPF_OP_MOV64_REG pc=30 dst=r0 src=r6 offset=0 imm=0
#line 58 "sample/cgroup_count_connect6.c"
    r0 = r6;
    // EBPF_OP_EXIT pc=31 dst=r0 src=r0 offset=0 imm=0
#line 58 "sample/cgroup_count_connect6.c"
    return r0;
#line 58 "sample/cgroup_count_connect6.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        count_tcp_connect6,
        "cgroup~1",
        "cgroup/connect6",
        "count_tcp_connect6",
        count_tcp_connect6_maps,
        1,
        count_tcp_connect6_helpers,
        2,
        32,
        &count_tcp_connect6_program_type_guid,
        &count_tcp_connect6_attach_type_guid,
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
    version->minor = 9;
    version->revision = 0;
}

metadata_table_t cgroup_count_connect6_metadata_table = {
    sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version};
