// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from cgroup_mt_connect4.o

#define NO_CRT
#include "bpf2c.h"

#include <guiddef.h>
#include <wdm.h>
#include <wsk.h>

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
RTL_QUERY_REGISTRY_ROUTINE static _bpf2c_query_registry_routine;

#define metadata_table cgroup_mt_connect4##_metadata_table

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

static GUID tcp_mt_connect4_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID tcp_mt_connect4_attach_type_guid = {
    0xa82e37b1, 0xaee7, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
#pragma code_seg(push, "cgroup~1")
static uint64_t
tcp_mt_connect4(void* context)
#line 27 "sample/cgroup_mt_connect4.c"
{
#line 27 "sample/cgroup_mt_connect4.c"
    // Prologue
#line 27 "sample/cgroup_mt_connect4.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 27 "sample/cgroup_mt_connect4.c"
    register uint64_t r0 = 0;
#line 27 "sample/cgroup_mt_connect4.c"
    register uint64_t r1 = 0;
#line 27 "sample/cgroup_mt_connect4.c"
    register uint64_t r2 = 0;
#line 27 "sample/cgroup_mt_connect4.c"
    register uint64_t r3 = 0;
#line 27 "sample/cgroup_mt_connect4.c"
    register uint64_t r4 = 0;
#line 27 "sample/cgroup_mt_connect4.c"
    register uint64_t r5 = 0;
#line 27 "sample/cgroup_mt_connect4.c"
    register uint64_t r10 = 0;

#line 27 "sample/cgroup_mt_connect4.c"
    r1 = (uintptr_t)context;
#line 27 "sample/cgroup_mt_connect4.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_LDXW pc=0 dst=r2 src=r1 offset=44 imm=0
#line 27 "sample/cgroup_mt_connect4.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(44));
    // EBPF_OP_MOV64_IMM pc=1 dst=r0 src=r0 offset=0 imm=1
#line 27 "sample/cgroup_mt_connect4.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_JNE_IMM pc=2 dst=r2 src=r0 offset=20 imm=6
#line 27 "sample/cgroup_mt_connect4.c"
    if (r2 != IMMEDIATE(6))
#line 27 "sample/cgroup_mt_connect4.c"
        goto label_1;
    // EBPF_OP_LDXH pc=3 dst=r2 src=r1 offset=40 imm=0
#line 33 "sample/cgroup_mt_connect4.c"
    r2 = *(uint16_t*)(uintptr_t)(r1 + OFFSET(40));
    // EBPF_OP_MOV64_IMM pc=4 dst=r3 src=r0 offset=0 imm=7459
#line 33 "sample/cgroup_mt_connect4.c"
    r3 = IMMEDIATE(7459);
    // EBPF_OP_MOV64_IMM pc=5 dst=r0 src=r0 offset=0 imm=1
#line 33 "sample/cgroup_mt_connect4.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_JGT_REG pc=6 dst=r3 src=r2 offset=16 imm=0
#line 33 "sample/cgroup_mt_connect4.c"
    if (r3 > r2)
#line 33 "sample/cgroup_mt_connect4.c"
        goto label_1;
    // EBPF_OP_MOV64_IMM pc=7 dst=r0 src=r0 offset=0 imm=0
#line 33 "sample/cgroup_mt_connect4.c"
    r0 = IMMEDIATE(0);
    // EBPF_OP_MOV64_REG pc=8 dst=r3 src=r2 offset=0 imm=0
#line 33 "sample/cgroup_mt_connect4.c"
    r3 = r2;
    // EBPF_OP_BE pc=9 dst=r3 src=r0 offset=0 imm=16
#line 33 "sample/cgroup_mt_connect4.c"
    r3 = htobe16((uint16_t)r3);
#line 33 "sample/cgroup_mt_connect4.c"
    r3 &= UINT32_MAX;
    // EBPF_OP_LDDW pc=10 dst=r4 src=r0 offset=0 imm=-1431655765
#line 33 "sample/cgroup_mt_connect4.c"
    r4 = (uint64_t)12297829382473034411;
    // EBPF_OP_MOV64_REG pc=12 dst=r5 src=r3 offset=0 imm=0
#line 41 "sample/cgroup_mt_connect4.c"
    r5 = r3;
    // EBPF_OP_MUL64_REG pc=13 dst=r5 src=r4 offset=0 imm=0
#line 41 "sample/cgroup_mt_connect4.c"
    r5 *= r4;
    // EBPF_OP_LDDW pc=14 dst=r4 src=r0 offset=0 imm=1431655766
#line 41 "sample/cgroup_mt_connect4.c"
    r4 = (uint64_t)6148914691236517206;
    // EBPF_OP_JGT_REG pc=16 dst=r4 src=r5 offset=6 imm=0
#line 41 "sample/cgroup_mt_connect4.c"
    if (r4 > r5)
#line 41 "sample/cgroup_mt_connect4.c"
        goto label_1;
    // EBPF_OP_AND64_IMM pc=17 dst=r3 src=r0 offset=0 imm=1
#line 46 "sample/cgroup_mt_connect4.c"
    r3 &= IMMEDIATE(1);
    // EBPF_OP_MOV64_IMM pc=18 dst=r0 src=r0 offset=0 imm=1
#line 46 "sample/cgroup_mt_connect4.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=19 dst=r3 src=r0 offset=3 imm=0
#line 46 "sample/cgroup_mt_connect4.c"
    if (r3 == IMMEDIATE(0))
#line 46 "sample/cgroup_mt_connect4.c"
        goto label_1;
    // EBPF_OP_ADD64_IMM pc=20 dst=r2 src=r0 offset=0 imm=-6141
#line 54 "sample/cgroup_mt_connect4.c"
    r2 += IMMEDIATE(-6141);
    // EBPF_OP_STXH pc=21 dst=r1 src=r2 offset=40 imm=0
#line 54 "sample/cgroup_mt_connect4.c"
    *(uint16_t*)(uintptr_t)(r1 + OFFSET(40)) = (uint16_t)r2;
    // EBPF_OP_MOV64_IMM pc=22 dst=r0 src=r0 offset=0 imm=1
#line 54 "sample/cgroup_mt_connect4.c"
    r0 = IMMEDIATE(1);
label_1:
    // EBPF_OP_EXIT pc=23 dst=r0 src=r0 offset=0 imm=0
#line 58 "sample/cgroup_mt_connect4.c"
    return r0;
#line 58 "sample/cgroup_mt_connect4.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        tcp_mt_connect4,
        "cgroup~1",
        "cgroup/connect4",
        "tcp_mt_connect4",
        NULL,
        0,
        NULL,
        0,
        24,
        &tcp_mt_connect4_program_type_guid,
        &tcp_mt_connect4_attach_type_guid,
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

metadata_table_t cgroup_mt_connect4_metadata_table = {
    sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version};
