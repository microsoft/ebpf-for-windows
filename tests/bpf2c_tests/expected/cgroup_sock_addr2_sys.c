// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from cgroup_sock_addr2.o

#define NO_CRT
#include "bpf2c.h"

#include <guiddef.h>
#include <wdm.h>
#include <wsk.h>

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
RTL_QUERY_REGISTRY_ROUTINE static _bpf2c_query_registry_routine;

#define metadata_table cgroup_sock_addr2##_metadata_table

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
         24,                // Size in bytes of a map key.
         24,                // Size in bytes of a map value.
         100,               // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         PIN_NONE,          // Pinning type for the map.
         0,                 // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "policy_map"},
    {NULL,
     {
         BPF_MAP_TYPE_HASH, // Type of map.
         8,                 // Size in bytes of a map key.
         24,                // Size in bytes of a map value.
         100,               // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         PIN_NONE,          // Pinning type for the map.
         0,                 // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "audit_map"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 2;
}

static helper_function_entry_t connect_redirect4_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 14, "helper_id_14"},
    {NULL, 65536, "helper_id_65536"},
    {NULL, 20, "helper_id_20"},
    {NULL, 21, "helper_id_21"},
    {NULL, 2, "helper_id_2"},
};

static GUID connect_redirect4_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID connect_redirect4_attach_type_guid = {
    0xa82e37b1, 0xaee7, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static uint16_t connect_redirect4_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "cgroup~1")
static uint64_t
connect_redirect4(void* context)
#line 121 "sample/cgroup_sock_addr2.c"
{
#line 121 "sample/cgroup_sock_addr2.c"
    // Prologue
#line 121 "sample/cgroup_sock_addr2.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 121 "sample/cgroup_sock_addr2.c"
    register uint64_t r0 = 0;
#line 121 "sample/cgroup_sock_addr2.c"
    register uint64_t r1 = 0;
#line 121 "sample/cgroup_sock_addr2.c"
    register uint64_t r2 = 0;
#line 121 "sample/cgroup_sock_addr2.c"
    register uint64_t r3 = 0;
#line 121 "sample/cgroup_sock_addr2.c"
    register uint64_t r4 = 0;
#line 121 "sample/cgroup_sock_addr2.c"
    register uint64_t r5 = 0;
#line 121 "sample/cgroup_sock_addr2.c"
    register uint64_t r6 = 0;
#line 121 "sample/cgroup_sock_addr2.c"
    register uint64_t r7 = 0;
#line 121 "sample/cgroup_sock_addr2.c"
    register uint64_t r8 = 0;
#line 121 "sample/cgroup_sock_addr2.c"
    register uint64_t r9 = 0;
#line 121 "sample/cgroup_sock_addr2.c"
    register uint64_t r10 = 0;

#line 121 "sample/cgroup_sock_addr2.c"
    r1 = (uintptr_t)context;
#line 121 "sample/cgroup_sock_addr2.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 121 "sample/cgroup_sock_addr2.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r7 src=r0 offset=0 imm=0
#line 121 "sample/cgroup_sock_addr2.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r7 offset=-16 imm=0
#line 55 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r7;
    // EBPF_OP_STXW pc=3 dst=r10 src=r7 offset=-20 imm=0
#line 55 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-20)) = (uint32_t)r7;
    // EBPF_OP_STXW pc=4 dst=r10 src=r7 offset=-24 imm=0
#line 55 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r7;
    // EBPF_OP_STXW pc=5 dst=r10 src=r7 offset=-28 imm=0
#line 55 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-28)) = (uint32_t)r7;
    // EBPF_OP_LDXW pc=6 dst=r1 src=r6 offset=24 imm=0
#line 56 "sample/cgroup_sock_addr2.c"
    r1 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(24));
    // EBPF_OP_STXW pc=7 dst=r10 src=r1 offset=-32 imm=0
#line 56 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint32_t)r1;
    // EBPF_OP_LDXH pc=8 dst=r1 src=r6 offset=40 imm=0
#line 57 "sample/cgroup_sock_addr2.c"
    r1 = *(uint16_t*)(uintptr_t)(r6 + OFFSET(40));
    // EBPF_OP_STXH pc=9 dst=r10 src=r1 offset=-16 imm=0
#line 57 "sample/cgroup_sock_addr2.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint16_t)r1;
    // EBPF_OP_LDXW pc=10 dst=r1 src=r6 offset=44 imm=0
#line 58 "sample/cgroup_sock_addr2.c"
    r1 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(44));
    // EBPF_OP_STXW pc=11 dst=r10 src=r1 offset=-12 imm=0
#line 58 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-12)) = (uint32_t)r1;
    // EBPF_OP_JEQ_IMM pc=12 dst=r1 src=r0 offset=1 imm=17
#line 60 "sample/cgroup_sock_addr2.c"
    if (r1 == IMMEDIATE(17))
#line 60 "sample/cgroup_sock_addr2.c"
        goto label_1;
    // EBPF_OP_JNE_IMM pc=13 dst=r1 src=r0 offset=62 imm=6
#line 60 "sample/cgroup_sock_addr2.c"
    if (r1 != IMMEDIATE(6))
#line 60 "sample/cgroup_sock_addr2.c"
        goto label_3;
label_1:
    // EBPF_OP_LDXW pc=14 dst=r1 src=r6 offset=0 imm=0
#line 64 "sample/cgroup_sock_addr2.c"
    r1 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=15 dst=r1 src=r0 offset=60 imm=2
#line 64 "sample/cgroup_sock_addr2.c"
    if (r1 != IMMEDIATE(2))
#line 64 "sample/cgroup_sock_addr2.c"
        goto label_3;
    // EBPF_OP_MOV64_REG pc=16 dst=r2 src=r10 offset=0 imm=0
#line 64 "sample/cgroup_sock_addr2.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=17 dst=r2 src=r0 offset=0 imm=-32
#line 69 "sample/cgroup_sock_addr2.c"
    r2 += IMMEDIATE(-32);
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=0
#line 69 "sample/cgroup_sock_addr2.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=20 dst=r0 src=r0 offset=0 imm=1
#line 69 "sample/cgroup_sock_addr2.c"
    r0 = connect_redirect4_helpers[0].address
#line 69 "sample/cgroup_sock_addr2.c"
         (r1, r2, r3, r4, r5);
#line 69 "sample/cgroup_sock_addr2.c"
    if ((connect_redirect4_helpers[0].tail_call) && (r0 == 0))
#line 69 "sample/cgroup_sock_addr2.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=21 dst=r8 src=r0 offset=0 imm=0
#line 69 "sample/cgroup_sock_addr2.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=22 dst=r9 src=r0 offset=0 imm=0
#line 69 "sample/cgroup_sock_addr2.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_MOV64_IMM pc=23 dst=r7 src=r0 offset=0 imm=0
#line 69 "sample/cgroup_sock_addr2.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_JEQ_IMM pc=24 dst=r8 src=r0 offset=27 imm=0
#line 70 "sample/cgroup_sock_addr2.c"
    if (r8 == IMMEDIATE(0))
#line 70 "sample/cgroup_sock_addr2.c"
        goto label_2;
    // EBPF_OP_MOV64_IMM pc=25 dst=r1 src=r0 offset=0 imm=0
#line 70 "sample/cgroup_sock_addr2.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=26 dst=r10 src=r1 offset=-38 imm=0
#line 71 "sample/cgroup_sock_addr2.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-38)) = (uint8_t)r1;
    // EBPF_OP_MOV64_IMM pc=27 dst=r1 src=r0 offset=0 imm=29989
#line 71 "sample/cgroup_sock_addr2.c"
    r1 = IMMEDIATE(29989);
    // EBPF_OP_STXH pc=28 dst=r10 src=r1 offset=-40 imm=0
#line 71 "sample/cgroup_sock_addr2.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=29 dst=r1 src=r0 offset=0 imm=540697973
#line 71 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)2318356710503900533;
    // EBPF_OP_STXDW pc=31 dst=r10 src=r1 offset=-48 imm=0
#line 71 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=32 dst=r1 src=r0 offset=0 imm=2037544046
#line 71 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)7809653110685725806;
    // EBPF_OP_STXDW pc=34 dst=r10 src=r1 offset=-56 imm=0
#line 71 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=35 dst=r1 src=r0 offset=0 imm=1869770784
#line 71 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)7286957755258269728;
    // EBPF_OP_STXDW pc=37 dst=r10 src=r1 offset=-64 imm=0
#line 71 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=38 dst=r1 src=r0 offset=0 imm=1853189958
#line 71 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)3780244552946118470;
    // EBPF_OP_STXDW pc=40 dst=r10 src=r1 offset=-72 imm=0
#line 71 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r1;
    // EBPF_OP_LDXH pc=41 dst=r4 src=r8 offset=16 imm=0
#line 71 "sample/cgroup_sock_addr2.c"
    r4 = *(uint16_t*)(uintptr_t)(r8 + OFFSET(16));
    // EBPF_OP_LDXW pc=42 dst=r3 src=r8 offset=0 imm=0
#line 71 "sample/cgroup_sock_addr2.c"
    r3 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=43 dst=r1 src=r10 offset=0 imm=0
#line 71 "sample/cgroup_sock_addr2.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=44 dst=r1 src=r0 offset=0 imm=-72
#line 71 "sample/cgroup_sock_addr2.c"
    r1 += IMMEDIATE(-72);
    // EBPF_OP_MOV64_IMM pc=45 dst=r2 src=r0 offset=0 imm=35
#line 71 "sample/cgroup_sock_addr2.c"
    r2 = IMMEDIATE(35);
    // EBPF_OP_CALL pc=46 dst=r0 src=r0 offset=0 imm=14
#line 71 "sample/cgroup_sock_addr2.c"
    r0 = connect_redirect4_helpers[1].address
#line 71 "sample/cgroup_sock_addr2.c"
         (r1, r2, r3, r4, r5);
#line 71 "sample/cgroup_sock_addr2.c"
    if ((connect_redirect4_helpers[1].tail_call) && (r0 == 0))
#line 71 "sample/cgroup_sock_addr2.c"
        return 0;
    // EBPF_OP_LDXW pc=47 dst=r1 src=r8 offset=0 imm=0
#line 72 "sample/cgroup_sock_addr2.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_STXW pc=48 dst=r6 src=r1 offset=24 imm=0
#line 72 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r6 + OFFSET(24)) = (uint32_t)r1;
    // EBPF_OP_LDXH pc=49 dst=r1 src=r8 offset=16 imm=0
#line 73 "sample/cgroup_sock_addr2.c"
    r1 = *(uint16_t*)(uintptr_t)(r8 + OFFSET(16));
    // EBPF_OP_STXH pc=50 dst=r6 src=r1 offset=40 imm=0
#line 73 "sample/cgroup_sock_addr2.c"
    *(uint16_t*)(uintptr_t)(r6 + OFFSET(40)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=51 dst=r7 src=r0 offset=0 imm=1
#line 73 "sample/cgroup_sock_addr2.c"
    r7 = IMMEDIATE(1);
label_2:
    // EBPF_OP_STXDW pc=52 dst=r10 src=r9 offset=-56 imm=0
#line 41 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r9;
    // EBPF_OP_STXDW pc=53 dst=r10 src=r9 offset=-64 imm=0
#line 41 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r9;
    // EBPF_OP_STXDW pc=54 dst=r10 src=r9 offset=-72 imm=0
#line 41 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r9;
    // EBPF_OP_MOV64_REG pc=55 dst=r1 src=r6 offset=0 imm=0
#line 42 "sample/cgroup_sock_addr2.c"
    r1 = r6;
    // EBPF_OP_CALL pc=56 dst=r0 src=r0 offset=0 imm=65536
#line 42 "sample/cgroup_sock_addr2.c"
    r0 = connect_redirect4_helpers[2].address
#line 42 "sample/cgroup_sock_addr2.c"
         (r1, r2, r3, r4, r5);
#line 42 "sample/cgroup_sock_addr2.c"
    if ((connect_redirect4_helpers[2].tail_call) && (r0 == 0))
#line 42 "sample/cgroup_sock_addr2.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=57 dst=r8 src=r0 offset=0 imm=0
#line 42 "sample/cgroup_sock_addr2.c"
    r8 = r0;
    // EBPF_OP_STXDW pc=58 dst=r10 src=r8 offset=-64 imm=0
#line 42 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r8;
    // EBPF_OP_MOV64_REG pc=59 dst=r1 src=r6 offset=0 imm=0
#line 43 "sample/cgroup_sock_addr2.c"
    r1 = r6;
    // EBPF_OP_CALL pc=60 dst=r0 src=r0 offset=0 imm=20
#line 43 "sample/cgroup_sock_addr2.c"
    r0 = connect_redirect4_helpers[3].address
#line 43 "sample/cgroup_sock_addr2.c"
         (r1, r2, r3, r4, r5);
#line 43 "sample/cgroup_sock_addr2.c"
    if ((connect_redirect4_helpers[3].tail_call) && (r0 == 0))
#line 43 "sample/cgroup_sock_addr2.c"
        return 0;
    // EBPF_OP_STXDW pc=61 dst=r10 src=r0 offset=-72 imm=0
#line 43 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r0;
    // EBPF_OP_MOV64_REG pc=62 dst=r1 src=r6 offset=0 imm=0
#line 44 "sample/cgroup_sock_addr2.c"
    r1 = r6;
    // EBPF_OP_CALL pc=63 dst=r0 src=r0 offset=0 imm=21
#line 44 "sample/cgroup_sock_addr2.c"
    r0 = connect_redirect4_helpers[4].address
#line 44 "sample/cgroup_sock_addr2.c"
         (r1, r2, r3, r4, r5);
#line 44 "sample/cgroup_sock_addr2.c"
    if ((connect_redirect4_helpers[4].tail_call) && (r0 == 0))
#line 44 "sample/cgroup_sock_addr2.c"
        return 0;
    // EBPF_OP_STXW pc=64 dst=r10 src=r0 offset=-56 imm=0
#line 44 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint32_t)r0;
    // EBPF_OP_LDXH pc=65 dst=r1 src=r6 offset=20 imm=0
#line 45 "sample/cgroup_sock_addr2.c"
    r1 = *(uint16_t*)(uintptr_t)(r6 + OFFSET(20));
    // EBPF_OP_STXDW pc=66 dst=r10 src=r8 offset=-8 imm=0
#line 47 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint64_t)r8;
    // EBPF_OP_STXH pc=67 dst=r10 src=r1 offset=-52 imm=0
#line 45 "sample/cgroup_sock_addr2.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-52)) = (uint16_t)r1;
    // EBPF_OP_MOV64_REG pc=68 dst=r2 src=r10 offset=0 imm=0
#line 45 "sample/cgroup_sock_addr2.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=69 dst=r2 src=r0 offset=0 imm=-8
#line 45 "sample/cgroup_sock_addr2.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_REG pc=70 dst=r3 src=r10 offset=0 imm=0
#line 45 "sample/cgroup_sock_addr2.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=71 dst=r3 src=r0 offset=0 imm=-72
#line 45 "sample/cgroup_sock_addr2.c"
    r3 += IMMEDIATE(-72);
    // EBPF_OP_LDDW pc=72 dst=r1 src=r0 offset=0 imm=0
#line 48 "sample/cgroup_sock_addr2.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_MOV64_IMM pc=74 dst=r4 src=r0 offset=0 imm=0
#line 48 "sample/cgroup_sock_addr2.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=75 dst=r0 src=r0 offset=0 imm=2
#line 48 "sample/cgroup_sock_addr2.c"
    r0 = connect_redirect4_helpers[5].address
#line 48 "sample/cgroup_sock_addr2.c"
         (r1, r2, r3, r4, r5);
#line 48 "sample/cgroup_sock_addr2.c"
    if ((connect_redirect4_helpers[5].tail_call) && (r0 == 0))
#line 48 "sample/cgroup_sock_addr2.c"
        return 0;
label_3:
    // EBPF_OP_MOV64_REG pc=76 dst=r0 src=r7 offset=0 imm=0
#line 123 "sample/cgroup_sock_addr2.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=77 dst=r0 src=r0 offset=0 imm=0
#line 123 "sample/cgroup_sock_addr2.c"
    return r0;
#line 123 "sample/cgroup_sock_addr2.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t connect_redirect6_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 12, "helper_id_12"},
    {NULL, 65536, "helper_id_65536"},
    {NULL, 20, "helper_id_20"},
    {NULL, 21, "helper_id_21"},
    {NULL, 2, "helper_id_2"},
};

static GUID connect_redirect6_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID connect_redirect6_attach_type_guid = {
    0xa82e37b2, 0xaee7, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static uint16_t connect_redirect6_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "cgroup~2")
static uint64_t
connect_redirect6(void* context)
#line 128 "sample/cgroup_sock_addr2.c"
{
#line 128 "sample/cgroup_sock_addr2.c"
    // Prologue
#line 128 "sample/cgroup_sock_addr2.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 128 "sample/cgroup_sock_addr2.c"
    register uint64_t r0 = 0;
#line 128 "sample/cgroup_sock_addr2.c"
    register uint64_t r1 = 0;
#line 128 "sample/cgroup_sock_addr2.c"
    register uint64_t r2 = 0;
#line 128 "sample/cgroup_sock_addr2.c"
    register uint64_t r3 = 0;
#line 128 "sample/cgroup_sock_addr2.c"
    register uint64_t r4 = 0;
#line 128 "sample/cgroup_sock_addr2.c"
    register uint64_t r5 = 0;
#line 128 "sample/cgroup_sock_addr2.c"
    register uint64_t r6 = 0;
#line 128 "sample/cgroup_sock_addr2.c"
    register uint64_t r7 = 0;
#line 128 "sample/cgroup_sock_addr2.c"
    register uint64_t r8 = 0;
#line 128 "sample/cgroup_sock_addr2.c"
    register uint64_t r9 = 0;
#line 128 "sample/cgroup_sock_addr2.c"
    register uint64_t r10 = 0;

#line 128 "sample/cgroup_sock_addr2.c"
    r1 = (uintptr_t)context;
#line 128 "sample/cgroup_sock_addr2.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 128 "sample/cgroup_sock_addr2.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r7 src=r0 offset=0 imm=0
#line 128 "sample/cgroup_sock_addr2.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=2 dst=r10 src=r7 offset=-16 imm=0
#line 87 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r7;
    // EBPF_OP_STXDW pc=3 dst=r10 src=r7 offset=-24 imm=0
#line 87 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r7;
    // EBPF_OP_STXDW pc=4 dst=r10 src=r7 offset=-32 imm=0
#line 87 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r7;
    // EBPF_OP_LDXW pc=5 dst=r1 src=r6 offset=44 imm=0
#line 89 "sample/cgroup_sock_addr2.c"
    r1 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(44));
    // EBPF_OP_JEQ_IMM pc=6 dst=r1 src=r0 offset=1 imm=17
#line 89 "sample/cgroup_sock_addr2.c"
    if (r1 == IMMEDIATE(17))
#line 89 "sample/cgroup_sock_addr2.c"
        goto label_1;
    // EBPF_OP_JNE_IMM pc=7 dst=r1 src=r0 offset=78 imm=6
#line 89 "sample/cgroup_sock_addr2.c"
    if (r1 != IMMEDIATE(6))
#line 89 "sample/cgroup_sock_addr2.c"
        goto label_3;
label_1:
    // EBPF_OP_LDXW pc=8 dst=r2 src=r6 offset=0 imm=0
#line 93 "sample/cgroup_sock_addr2.c"
    r2 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_JNE_IMM pc=9 dst=r2 src=r0 offset=76 imm=23
#line 93 "sample/cgroup_sock_addr2.c"
    if (r2 != IMMEDIATE(23))
#line 93 "sample/cgroup_sock_addr2.c"
        goto label_3;
    // EBPF_OP_LDXW pc=10 dst=r2 src=r6 offset=36 imm=0
#line 100 "sample/cgroup_sock_addr2.c"
    r2 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(36));
    // EBPF_OP_LSH64_IMM pc=11 dst=r2 src=r0 offset=0 imm=32
#line 100 "sample/cgroup_sock_addr2.c"
    r2 <<= IMMEDIATE(32);
    // EBPF_OP_LDXW pc=12 dst=r3 src=r6 offset=32 imm=0
#line 100 "sample/cgroup_sock_addr2.c"
    r3 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(32));
    // EBPF_OP_OR64_REG pc=13 dst=r2 src=r3 offset=0 imm=0
#line 100 "sample/cgroup_sock_addr2.c"
    r2 |= r3;
    // EBPF_OP_STXDW pc=14 dst=r10 src=r2 offset=-24 imm=0
#line 100 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r2;
    // EBPF_OP_LDXW pc=15 dst=r2 src=r6 offset=28 imm=0
#line 100 "sample/cgroup_sock_addr2.c"
    r2 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(28));
    // EBPF_OP_LSH64_IMM pc=16 dst=r2 src=r0 offset=0 imm=32
#line 100 "sample/cgroup_sock_addr2.c"
    r2 <<= IMMEDIATE(32);
    // EBPF_OP_LDXW pc=17 dst=r3 src=r6 offset=24 imm=0
#line 100 "sample/cgroup_sock_addr2.c"
    r3 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(24));
    // EBPF_OP_OR64_REG pc=18 dst=r2 src=r3 offset=0 imm=0
#line 100 "sample/cgroup_sock_addr2.c"
    r2 |= r3;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r2 offset=-32 imm=0
#line 100 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r2;
    // EBPF_OP_LDXH pc=20 dst=r2 src=r6 offset=40 imm=0
#line 101 "sample/cgroup_sock_addr2.c"
    r2 = *(uint16_t*)(uintptr_t)(r6 + OFFSET(40));
    // EBPF_OP_STXH pc=21 dst=r10 src=r2 offset=-16 imm=0
#line 101 "sample/cgroup_sock_addr2.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint16_t)r2;
    // EBPF_OP_STXW pc=22 dst=r10 src=r1 offset=-12 imm=0
#line 102 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-12)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=23 dst=r2 src=r10 offset=0 imm=0
#line 102 "sample/cgroup_sock_addr2.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=24 dst=r2 src=r0 offset=0 imm=-32
#line 100 "sample/cgroup_sock_addr2.c"
    r2 += IMMEDIATE(-32);
    // EBPF_OP_LDDW pc=25 dst=r1 src=r0 offset=0 imm=0
#line 105 "sample/cgroup_sock_addr2.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=27 dst=r0 src=r0 offset=0 imm=1
#line 105 "sample/cgroup_sock_addr2.c"
    r0 = connect_redirect6_helpers[0].address
#line 105 "sample/cgroup_sock_addr2.c"
         (r1, r2, r3, r4, r5);
#line 105 "sample/cgroup_sock_addr2.c"
    if ((connect_redirect6_helpers[0].tail_call) && (r0 == 0))
#line 105 "sample/cgroup_sock_addr2.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=28 dst=r8 src=r0 offset=0 imm=0
#line 105 "sample/cgroup_sock_addr2.c"
    r8 = r0;
    // EBPF_OP_MOV64_IMM pc=29 dst=r9 src=r0 offset=0 imm=0
#line 105 "sample/cgroup_sock_addr2.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_MOV64_IMM pc=30 dst=r7 src=r0 offset=0 imm=0
#line 105 "sample/cgroup_sock_addr2.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_JEQ_IMM pc=31 dst=r8 src=r0 offset=30 imm=0
#line 106 "sample/cgroup_sock_addr2.c"
    if (r8 == IMMEDIATE(0))
#line 106 "sample/cgroup_sock_addr2.c"
        goto label_2;
    // EBPF_OP_MOV64_REG pc=32 dst=r7 src=r6 offset=0 imm=0
#line 106 "sample/cgroup_sock_addr2.c"
    r7 = r6;
    // EBPF_OP_ADD64_IMM pc=33 dst=r7 src=r0 offset=0 imm=24
#line 106 "sample/cgroup_sock_addr2.c"
    r7 += IMMEDIATE(24);
    // EBPF_OP_MOV64_IMM pc=34 dst=r1 src=r0 offset=0 imm=0
#line 106 "sample/cgroup_sock_addr2.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=35 dst=r10 src=r1 offset=-38 imm=0
#line 107 "sample/cgroup_sock_addr2.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-38)) = (uint8_t)r1;
    // EBPF_OP_MOV64_IMM pc=36 dst=r1 src=r0 offset=0 imm=25973
#line 107 "sample/cgroup_sock_addr2.c"
    r1 = IMMEDIATE(25973);
    // EBPF_OP_STXH pc=37 dst=r10 src=r1 offset=-40 imm=0
#line 107 "sample/cgroup_sock_addr2.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=38 dst=r1 src=r0 offset=0 imm=2037544046
#line 107 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)7809653110685725806;
    // EBPF_OP_STXDW pc=40 dst=r10 src=r1 offset=-48 imm=0
#line 107 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=41 dst=r1 src=r0 offset=0 imm=1869770784
#line 107 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)7286957755258269728;
    // EBPF_OP_STXDW pc=43 dst=r10 src=r1 offset=-56 imm=0
#line 107 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=44 dst=r1 src=r0 offset=0 imm=1853189958
#line 107 "sample/cgroup_sock_addr2.c"
    r1 = (uint64_t)3924359741021974342;
    // EBPF_OP_STXDW pc=46 dst=r10 src=r1 offset=-64 imm=0
#line 107 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=47 dst=r1 src=r10 offset=0 imm=0
#line 107 "sample/cgroup_sock_addr2.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=48 dst=r1 src=r0 offset=0 imm=-64
#line 107 "sample/cgroup_sock_addr2.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=49 dst=r2 src=r0 offset=0 imm=27
#line 107 "sample/cgroup_sock_addr2.c"
    r2 = IMMEDIATE(27);
    // EBPF_OP_CALL pc=50 dst=r0 src=r0 offset=0 imm=12
#line 107 "sample/cgroup_sock_addr2.c"
    r0 = connect_redirect6_helpers[1].address
#line 107 "sample/cgroup_sock_addr2.c"
         (r1, r2, r3, r4, r5);
#line 107 "sample/cgroup_sock_addr2.c"
    if ((connect_redirect6_helpers[1].tail_call) && (r0 == 0))
#line 107 "sample/cgroup_sock_addr2.c"
        return 0;
    // EBPF_OP_LDXW pc=51 dst=r1 src=r8 offset=12 imm=0
#line 108 "sample/cgroup_sock_addr2.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(12));
    // EBPF_OP_STXW pc=52 dst=r7 src=r1 offset=12 imm=0
#line 108 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r7 + OFFSET(12)) = (uint32_t)r1;
    // EBPF_OP_LDXW pc=53 dst=r1 src=r8 offset=8 imm=0
#line 108 "sample/cgroup_sock_addr2.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(8));
    // EBPF_OP_STXW pc=54 dst=r7 src=r1 offset=8 imm=0
#line 108 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r7 + OFFSET(8)) = (uint32_t)r1;
    // EBPF_OP_LDXW pc=55 dst=r1 src=r8 offset=4 imm=0
#line 108 "sample/cgroup_sock_addr2.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(4));
    // EBPF_OP_STXW pc=56 dst=r7 src=r1 offset=4 imm=0
#line 108 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r7 + OFFSET(4)) = (uint32_t)r1;
    // EBPF_OP_LDXW pc=57 dst=r1 src=r8 offset=0 imm=0
#line 108 "sample/cgroup_sock_addr2.c"
    r1 = *(uint32_t*)(uintptr_t)(r8 + OFFSET(0));
    // EBPF_OP_STXW pc=58 dst=r7 src=r1 offset=0 imm=0
#line 108 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r7 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_LDXH pc=59 dst=r1 src=r8 offset=16 imm=0
#line 109 "sample/cgroup_sock_addr2.c"
    r1 = *(uint16_t*)(uintptr_t)(r8 + OFFSET(16));
    // EBPF_OP_STXH pc=60 dst=r6 src=r1 offset=40 imm=0
#line 109 "sample/cgroup_sock_addr2.c"
    *(uint16_t*)(uintptr_t)(r6 + OFFSET(40)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=61 dst=r7 src=r0 offset=0 imm=1
#line 109 "sample/cgroup_sock_addr2.c"
    r7 = IMMEDIATE(1);
label_2:
    // EBPF_OP_STXDW pc=62 dst=r10 src=r9 offset=-48 imm=0
#line 41 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r9;
    // EBPF_OP_STXDW pc=63 dst=r10 src=r9 offset=-56 imm=0
#line 41 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r9;
    // EBPF_OP_STXDW pc=64 dst=r10 src=r9 offset=-64 imm=0
#line 41 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r9;
    // EBPF_OP_MOV64_REG pc=65 dst=r1 src=r6 offset=0 imm=0
#line 42 "sample/cgroup_sock_addr2.c"
    r1 = r6;
    // EBPF_OP_CALL pc=66 dst=r0 src=r0 offset=0 imm=65536
#line 42 "sample/cgroup_sock_addr2.c"
    r0 = connect_redirect6_helpers[2].address
#line 42 "sample/cgroup_sock_addr2.c"
         (r1, r2, r3, r4, r5);
#line 42 "sample/cgroup_sock_addr2.c"
    if ((connect_redirect6_helpers[2].tail_call) && (r0 == 0))
#line 42 "sample/cgroup_sock_addr2.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=67 dst=r8 src=r0 offset=0 imm=0
#line 42 "sample/cgroup_sock_addr2.c"
    r8 = r0;
    // EBPF_OP_STXDW pc=68 dst=r10 src=r8 offset=-56 imm=0
#line 42 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r8;
    // EBPF_OP_MOV64_REG pc=69 dst=r1 src=r6 offset=0 imm=0
#line 43 "sample/cgroup_sock_addr2.c"
    r1 = r6;
    // EBPF_OP_CALL pc=70 dst=r0 src=r0 offset=0 imm=20
#line 43 "sample/cgroup_sock_addr2.c"
    r0 = connect_redirect6_helpers[3].address
#line 43 "sample/cgroup_sock_addr2.c"
         (r1, r2, r3, r4, r5);
#line 43 "sample/cgroup_sock_addr2.c"
    if ((connect_redirect6_helpers[3].tail_call) && (r0 == 0))
#line 43 "sample/cgroup_sock_addr2.c"
        return 0;
    // EBPF_OP_STXDW pc=71 dst=r10 src=r0 offset=-64 imm=0
#line 43 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r0;
    // EBPF_OP_MOV64_REG pc=72 dst=r1 src=r6 offset=0 imm=0
#line 44 "sample/cgroup_sock_addr2.c"
    r1 = r6;
    // EBPF_OP_CALL pc=73 dst=r0 src=r0 offset=0 imm=21
#line 44 "sample/cgroup_sock_addr2.c"
    r0 = connect_redirect6_helpers[4].address
#line 44 "sample/cgroup_sock_addr2.c"
         (r1, r2, r3, r4, r5);
#line 44 "sample/cgroup_sock_addr2.c"
    if ((connect_redirect6_helpers[4].tail_call) && (r0 == 0))
#line 44 "sample/cgroup_sock_addr2.c"
        return 0;
    // EBPF_OP_STXW pc=74 dst=r10 src=r0 offset=-48 imm=0
#line 44 "sample/cgroup_sock_addr2.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint32_t)r0;
    // EBPF_OP_LDXH pc=75 dst=r1 src=r6 offset=20 imm=0
#line 45 "sample/cgroup_sock_addr2.c"
    r1 = *(uint16_t*)(uintptr_t)(r6 + OFFSET(20));
    // EBPF_OP_STXDW pc=76 dst=r10 src=r8 offset=-8 imm=0
#line 47 "sample/cgroup_sock_addr2.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint64_t)r8;
    // EBPF_OP_STXH pc=77 dst=r10 src=r1 offset=-44 imm=0
#line 45 "sample/cgroup_sock_addr2.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-44)) = (uint16_t)r1;
    // EBPF_OP_MOV64_REG pc=78 dst=r2 src=r10 offset=0 imm=0
#line 45 "sample/cgroup_sock_addr2.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=79 dst=r2 src=r0 offset=0 imm=-8
#line 45 "sample/cgroup_sock_addr2.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_REG pc=80 dst=r3 src=r10 offset=0 imm=0
#line 45 "sample/cgroup_sock_addr2.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=81 dst=r3 src=r0 offset=0 imm=-64
#line 45 "sample/cgroup_sock_addr2.c"
    r3 += IMMEDIATE(-64);
    // EBPF_OP_LDDW pc=82 dst=r1 src=r0 offset=0 imm=0
#line 48 "sample/cgroup_sock_addr2.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_MOV64_IMM pc=84 dst=r4 src=r0 offset=0 imm=0
#line 48 "sample/cgroup_sock_addr2.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=85 dst=r0 src=r0 offset=0 imm=2
#line 48 "sample/cgroup_sock_addr2.c"
    r0 = connect_redirect6_helpers[5].address
#line 48 "sample/cgroup_sock_addr2.c"
         (r1, r2, r3, r4, r5);
#line 48 "sample/cgroup_sock_addr2.c"
    if ((connect_redirect6_helpers[5].tail_call) && (r0 == 0))
#line 48 "sample/cgroup_sock_addr2.c"
        return 0;
label_3:
    // EBPF_OP_MOV64_REG pc=86 dst=r0 src=r7 offset=0 imm=0
#line 130 "sample/cgroup_sock_addr2.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=87 dst=r0 src=r0 offset=0 imm=0
#line 130 "sample/cgroup_sock_addr2.c"
    return r0;
#line 130 "sample/cgroup_sock_addr2.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        connect_redirect4,
        "cgroup~1",
        "cgroup/connect4",
        "connect_redirect4",
        connect_redirect4_maps,
        2,
        connect_redirect4_helpers,
        6,
        78,
        &connect_redirect4_program_type_guid,
        &connect_redirect4_attach_type_guid,
    },
    {
        0,
        connect_redirect6,
        "cgroup~2",
        "cgroup/connect6",
        "connect_redirect6",
        connect_redirect6_maps,
        2,
        connect_redirect6_helpers,
        6,
        88,
        &connect_redirect6_program_type_guid,
        &connect_redirect6_attach_type_guid,
    },
};
#pragma data_seg(pop)

static void
_get_programs(_Outptr_result_buffer_(*count) program_entry_t** programs, _Out_ size_t* count)
{
    *programs = _programs;
    *count = 2;
}

static void
_get_version(_Out_ bpf2c_version_t* version)
{
    version->major = 0;
    version->minor = 9;
    version->revision = 0;
}

metadata_table_t cgroup_sock_addr2_metadata_table = {
    sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version};
