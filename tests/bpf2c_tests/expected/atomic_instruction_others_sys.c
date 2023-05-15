// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from atomic_instruction_others.o

#define NO_CRT
#include "bpf2c.h"

#include <guiddef.h>
#include <wdm.h>
#include <wsk.h>

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
RTL_QUERY_REGISTRY_ROUTINE static _bpf2c_query_registry_routine;

#define metadata_table atomic_instruction_others##_metadata_table

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
static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = NULL;
    *count = 0;
}

static GUID test_program_type_guid = {0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID test_attach_type_guid = {0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
#pragma code_seg(push, "xdp_prog")
static uint64_t
test(void* context)
{
    // Prologue
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
    register uint64_t r0 = 0;
    register uint64_t r1 = 0;
    register uint64_t r2 = 0;
    register uint64_t r10 = 0;

    r1 = (uintptr_t)context;
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_STXDW pc=0 dst=r10 src=r1 offset=-8 imm=0
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint64_t)r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r2 src=r0 offset=0 imm=123
    r2 = IMMEDIATE(123);
    // EBPF_OP_STXDW pc=2 dst=r10 src=r2 offset=-16 imm=0
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r2;
    // EBPF_OP_MOV64_IMM pc=3 dst=r0 src=r0 offset=0 imm=3
    r0 = IMMEDIATE(3);
    // EBPF_OP_STXDW pc=4 dst=r10 src=r0 offset=-24 imm=0
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r0;
    // EBPF_OP_MOV64_IMM pc=5 dst=r1 src=r0 offset=0 imm=0
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=6 dst=r10 src=r1 offset=-56 imm=0
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=7 dst=r10 src=r1 offset=-32 imm=0
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_STXW pc=8 dst=r10 src=r2 offset=-36 imm=0
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-36)) = (uint32_t)r2;
    // EBPF_OP_STXW pc=9 dst=r10 src=r0 offset=-40 imm=0
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint32_t)r0;
    // EBPF_OP_STXW pc=10 dst=r10 src=r1 offset=-44 imm=0
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-44)) = (uint32_t)r1;
    // EBPF_OP_MOV64_IMM pc=11 dst=r1 src=r0 offset=0 imm=1
    r1 = IMMEDIATE(1);
    // EBPF_OP_MOV64_REG pc=12 dst=r2 src=r1 offset=0 imm=0
    r2 = r1;
    // EBPF_OP_ATOMIC64_ADD_FETCH pc=13 dst=r10 src=r2 offset=-16 imm=1
    r2 = (uint64_t)_InterlockedExchangeAdd64((volatile int64_t*)(uintptr_t)(r10 + OFFSET(-16)), (uint64_t)r2);
    // EBPF_OP_MOV64_IMM pc=14 dst=r2 src=r0 offset=0 imm=2
    r2 = IMMEDIATE(2);
    // EBPF_OP_ATOMIC64_OR_FETCH pc=15 dst=r10 src=r2 offset=-16 imm=65
    r2 = (uint64_t)_InterlockedOr64((volatile int64_t*)(uintptr_t)(r10 + OFFSET(-16)), (uint64_t)r2);
    // EBPF_OP_MOV64_REG pc=16 dst=r2 src=r0 offset=0 imm=0
    r2 = r0;
    // EBPF_OP_ATOMIC64_AND_FETCH pc=17 dst=r10 src=r2 offset=-16 imm=81
    r2 = (uint64_t)_InterlockedAnd64((volatile int64_t*)(uintptr_t)(r10 + OFFSET(-16)), (uint64_t)r2);
    // EBPF_OP_MOV64_IMM pc=18 dst=r2 src=r0 offset=0 imm=4
    r2 = IMMEDIATE(4);
    // EBPF_OP_ATOMIC64_XOR pc=19 dst=r10 src=r2 offset=-16 imm=160
    _InterlockedXor64((volatile int64_t*)(uintptr_t)(r10 + OFFSET(-16)), (uint64_t)r2);
    // EBPF_OP_ATOMIC_OR pc=20 dst=r10 src=r1 offset=-36 imm=64
    _InterlockedOr((volatile long*)(uintptr_t)(r10 + OFFSET(-36)), (uint32_t)r1);
    // EBPF_OP_LDXDW pc=21 dst=r1 src=r10 offset=-24 imm=0
    r1 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24));
    // EBPF_OP_ATOMIC64_XCHG pc=22 dst=r10 src=r1 offset=-16 imm=225
    _InterlockedExchange64((volatile int64_t*)(uintptr_t)(r10 + OFFSET(-16)), (uint64_t)r1);
    // EBPF_OP_STXDW pc=23 dst=r10 src=r1 offset=-32 imm=0
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_MOV64_IMM pc=24 dst=r1 src=r0 offset=0 imm=5
    r1 = IMMEDIATE(5);
    // EBPF_OP_ATOMIC64_CMPXCHG pc=25 dst=r10 src=r1 offset=-16 imm=241
    r0 = (uint64_t)_InterlockedCompareExchange64((volatile int64_t*)(uintptr_t)(r10 + OFFSET(-16)), (uint64_t)r1, r0);
    // EBPF_OP_LDXDW pc=26 dst=r0 src=r10 offset=-56 imm=0
    r0 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56));
    // EBPF_OP_EXIT pc=27 dst=r0 src=r0 offset=0 imm=0
    return r0;
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        test,
        "xdp_prog",
        "xdp_prog",
        "test",
        NULL,
        0,
        NULL,
        0,
        28,
        &test_program_type_guid,
        &test_attach_type_guid,
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

metadata_table_t atomic_instruction_others_metadata_table = {
    sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version};
