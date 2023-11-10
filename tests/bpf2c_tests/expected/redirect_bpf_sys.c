// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from redirect_bpf.o

#define NO_CRT
#include "bpf2c.h"

#include <guiddef.h>
#include <wdm.h>
#include <wsk.h>

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
RTL_QUERY_REGISTRY_ROUTINE static _bpf2c_query_registry_routine;

#define metadata_table redirect_bpf##_metadata_table

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
         10,                // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         LIBBPF_PIN_NONE,   // Pinning type for the map.
         0,                 // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "policy_map"},
    {NULL,
     {
         BPF_MAP_TYPE_HASH, // Type of map.
         4,                 // Size in bytes of a map key.
         4,                 // Size in bytes of a map value.
         10,                // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         LIBBPF_PIN_NONE,   // Pinning type for the map.
         0,                 // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "skip_process_map"},
    {NULL,
     {
         BPF_MAP_TYPE_LRU_HASH, // Type of map.
         8,                     // Size in bytes of a map key.
         24,                    // Size in bytes of a map value.
         1000,                  // Maximum number of entries allowed in the map.
         0,                     // Inner map index.
         LIBBPF_PIN_NONE,       // Pinning type for the map.
         0,                     // Identifier for a map template.
         0,                     // The id of the inner map template.
     },
     "audit_map"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 3;
}

static helper_function_entry_t authorize_connect4_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 14, "helper_id_14"},
    {NULL, 65536, "helper_id_65536"},
    {NULL, 20, "helper_id_20"},
    {NULL, 21, "helper_id_21"},
    {NULL, 65537, "helper_id_65537"},
    {NULL, 12, "helper_id_12"},
    {NULL, 2, "helper_id_2"},
};

static GUID authorize_connect4_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID authorize_connect4_attach_type_guid = {
    0xa82e37b1, 0xaee7, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static uint16_t authorize_connect4_maps[] = {
    0,
    1,
    2,
};

#pragma code_seg(push, "cgroup~1")
static uint64_t
authorize_connect4(void* context)
#line 109 "sample/redirect_bpf.c"
{
#line 109 "sample/redirect_bpf.c"
    // Prologue
#line 109 "sample/redirect_bpf.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 109 "sample/redirect_bpf.c"
    register uint64_t r0 = 0;
#line 109 "sample/redirect_bpf.c"
    register uint64_t r1 = 0;
#line 109 "sample/redirect_bpf.c"
    register uint64_t r2 = 0;
#line 109 "sample/redirect_bpf.c"
    register uint64_t r3 = 0;
#line 109 "sample/redirect_bpf.c"
    register uint64_t r4 = 0;
#line 109 "sample/redirect_bpf.c"
    register uint64_t r5 = 0;
#line 109 "sample/redirect_bpf.c"
    register uint64_t r6 = 0;
#line 109 "sample/redirect_bpf.c"
    register uint64_t r7 = 0;
#line 109 "sample/redirect_bpf.c"
    register uint64_t r8 = 0;
#line 109 "sample/redirect_bpf.c"
    register uint64_t r9 = 0;
#line 109 "sample/redirect_bpf.c"
    register uint64_t r10 = 0;

#line 109 "sample/redirect_bpf.c"
    r1 = (uintptr_t)context;
#line 109 "sample/redirect_bpf.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 109 "sample/redirect_bpf.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r8 src=r0 offset=0 imm=0
#line 109 "sample/redirect_bpf.c"
    r8 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2 dst=r10 src=r8 offset=-16 imm=0
#line 83 "sample/redirect_bpf.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r8;
    // EBPF_OP_STXW pc=3 dst=r10 src=r8 offset=-20 imm=0
#line 83 "sample/redirect_bpf.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-20)) = (uint32_t)r8;
    // EBPF_OP_STXW pc=4 dst=r10 src=r8 offset=-24 imm=0
#line 83 "sample/redirect_bpf.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r8;
    // EBPF_OP_STXW pc=5 dst=r10 src=r8 offset=-28 imm=0
#line 83 "sample/redirect_bpf.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-28)) = (uint32_t)r8;
    // EBPF_OP_LDXW pc=6 dst=r1 src=r6 offset=24 imm=0
#line 84 "sample/redirect_bpf.c"
    r1 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(24));
    // EBPF_OP_STXW pc=7 dst=r10 src=r1 offset=-32 imm=0
#line 84 "sample/redirect_bpf.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint32_t)r1;
    // EBPF_OP_LDXH pc=8 dst=r1 src=r6 offset=40 imm=0
#line 85 "sample/redirect_bpf.c"
    r1 = *(uint16_t*)(uintptr_t)(r6 + OFFSET(40));
    // EBPF_OP_STXH pc=9 dst=r10 src=r1 offset=-16 imm=0
#line 85 "sample/redirect_bpf.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint16_t)r1;
    // EBPF_OP_LDXW pc=10 dst=r1 src=r6 offset=44 imm=0
#line 86 "sample/redirect_bpf.c"
    r1 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(44));
    // EBPF_OP_STXW pc=11 dst=r10 src=r1 offset=-12 imm=0
#line 86 "sample/redirect_bpf.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-12)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=12 dst=r2 src=r10 offset=0 imm=0
#line 86 "sample/redirect_bpf.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=13 dst=r2 src=r0 offset=0 imm=-32
#line 86 "sample/redirect_bpf.c"
    r2 += IMMEDIATE(-32);
    // EBPF_OP_LDDW pc=14 dst=r1 src=r0 offset=0 imm=0
#line 89 "sample/redirect_bpf.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=16 dst=r0 src=r0 offset=0 imm=1
#line 89 "sample/redirect_bpf.c"
    r0 = authorize_connect4_helpers[0].address
#line 89 "sample/redirect_bpf.c"
         (r1, r2, r3, r4, r5);
#line 89 "sample/redirect_bpf.c"
    if ((authorize_connect4_helpers[0].tail_call) && (r0 == 0))
#line 89 "sample/redirect_bpf.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=17 dst=r7 src=r0 offset=0 imm=0
#line 89 "sample/redirect_bpf.c"
    r7 = r0;
    // EBPF_OP_JEQ_IMM pc=18 dst=r7 src=r0 offset=94 imm=0
#line 90 "sample/redirect_bpf.c"
    if (r7 == IMMEDIATE(0))
#line 90 "sample/redirect_bpf.c"
        goto label_4;
        // EBPF_OP_STXB pc=19 dst=r10 src=r8 offset=-46 imm=0
#line 91 "sample/redirect_bpf.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-46)) = (uint8_t)r8;
    // EBPF_OP_MOV64_IMM pc=20 dst=r1 src=r0 offset=0 imm=29989
#line 91 "sample/redirect_bpf.c"
    r1 = IMMEDIATE(29989);
    // EBPF_OP_STXH pc=21 dst=r10 src=r1 offset=-48 imm=0
#line 91 "sample/redirect_bpf.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=22 dst=r1 src=r0 offset=0 imm=540697973
#line 91 "sample/redirect_bpf.c"
    r1 = (uint64_t)2318356710503900533;
    // EBPF_OP_STXDW pc=24 dst=r10 src=r1 offset=-56 imm=0
#line 91 "sample/redirect_bpf.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=25 dst=r1 src=r0 offset=0 imm=2037544046
#line 91 "sample/redirect_bpf.c"
    r1 = (uint64_t)7809653110685725806;
    // EBPF_OP_STXDW pc=27 dst=r10 src=r1 offset=-64 imm=0
#line 91 "sample/redirect_bpf.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=28 dst=r1 src=r0 offset=0 imm=1869770784
#line 91 "sample/redirect_bpf.c"
    r1 = (uint64_t)7286957755258269728;
    // EBPF_OP_STXDW pc=30 dst=r10 src=r1 offset=-72 imm=0
#line 91 "sample/redirect_bpf.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=31 dst=r1 src=r0 offset=0 imm=1853189958
#line 91 "sample/redirect_bpf.c"
    r1 = (uint64_t)3780244552946118470;
    // EBPF_OP_STXDW pc=33 dst=r10 src=r1 offset=-80 imm=0
#line 91 "sample/redirect_bpf.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDXH pc=34 dst=r4 src=r7 offset=16 imm=0
#line 91 "sample/redirect_bpf.c"
    r4 = *(uint16_t*)(uintptr_t)(r7 + OFFSET(16));
    // EBPF_OP_LDXW pc=35 dst=r3 src=r7 offset=0 imm=0
#line 91 "sample/redirect_bpf.c"
    r3 = *(uint32_t*)(uintptr_t)(r7 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=36 dst=r1 src=r10 offset=0 imm=0
#line 91 "sample/redirect_bpf.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=37 dst=r1 src=r0 offset=0 imm=-80
#line 91 "sample/redirect_bpf.c"
    r1 += IMMEDIATE(-80);
    // EBPF_OP_MOV64_IMM pc=38 dst=r2 src=r0 offset=0 imm=35
#line 91 "sample/redirect_bpf.c"
    r2 = IMMEDIATE(35);
    // EBPF_OP_CALL pc=39 dst=r0 src=r0 offset=0 imm=14
#line 91 "sample/redirect_bpf.c"
    r0 = authorize_connect4_helpers[1].address
#line 91 "sample/redirect_bpf.c"
         (r1, r2, r3, r4, r5);
#line 91 "sample/redirect_bpf.c"
    if ((authorize_connect4_helpers[1].tail_call) && (r0 == 0))
#line 91 "sample/redirect_bpf.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=40 dst=r1 src=r6 offset=0 imm=0
#line 51 "sample/redirect_bpf.c"
    r1 = r6;
    // EBPF_OP_CALL pc=41 dst=r0 src=r0 offset=0 imm=65536
#line 51 "sample/redirect_bpf.c"
    r0 = authorize_connect4_helpers[2].address
#line 51 "sample/redirect_bpf.c"
         (r1, r2, r3, r4, r5);
#line 51 "sample/redirect_bpf.c"
    if ((authorize_connect4_helpers[2].tail_call) && (r0 == 0))
#line 51 "sample/redirect_bpf.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=42 dst=r8 src=r0 offset=0 imm=0
#line 51 "sample/redirect_bpf.c"
    r8 = r0;
    // EBPF_OP_RSH64_IMM pc=43 dst=r8 src=r0 offset=0 imm=32
#line 52 "sample/redirect_bpf.c"
    r8 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_STXW pc=44 dst=r10 src=r8 offset=-80 imm=0
#line 36 "sample/redirect_bpf.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint32_t)r8;
    // EBPF_OP_MOV64_REG pc=45 dst=r2 src=r10 offset=0 imm=0
#line 36 "sample/redirect_bpf.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=46 dst=r2 src=r0 offset=0 imm=-80
#line 36 "sample/redirect_bpf.c"
    r2 += IMMEDIATE(-80);
    // EBPF_OP_LDDW pc=47 dst=r1 src=r0 offset=0 imm=0
#line 39 "sample/redirect_bpf.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=49 dst=r0 src=r0 offset=0 imm=1
#line 39 "sample/redirect_bpf.c"
    r0 = authorize_connect4_helpers[0].address
#line 39 "sample/redirect_bpf.c"
         (r1, r2, r3, r4, r5);
#line 39 "sample/redirect_bpf.c"
    if ((authorize_connect4_helpers[0].tail_call) && (r0 == 0))
#line 39 "sample/redirect_bpf.c"
        return 0;
        // EBPF_OP_JNE_IMM pc=50 dst=r0 src=r0 offset=23 imm=0
#line 54 "sample/redirect_bpf.c"
    if (r0 != IMMEDIATE(0))
#line 54 "sample/redirect_bpf.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=51 dst=r9 src=r0 offset=0 imm=0
#line 54 "sample/redirect_bpf.c"
    r9 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=52 dst=r10 src=r9 offset=-72 imm=0
#line 58 "sample/redirect_bpf.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r9;
    // EBPF_OP_STXDW pc=53 dst=r10 src=r9 offset=-64 imm=0
#line 58 "sample/redirect_bpf.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r9;
    // EBPF_OP_STXDW pc=54 dst=r10 src=r9 offset=-80 imm=0
#line 58 "sample/redirect_bpf.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r9;
    // EBPF_OP_STXW pc=55 dst=r10 src=r8 offset=-72 imm=0
#line 59 "sample/redirect_bpf.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint32_t)r8;
    // EBPF_OP_MOV64_REG pc=56 dst=r1 src=r6 offset=0 imm=0
#line 60 "sample/redirect_bpf.c"
    r1 = r6;
    // EBPF_OP_CALL pc=57 dst=r0 src=r0 offset=0 imm=20
#line 60 "sample/redirect_bpf.c"
    r0 = authorize_connect4_helpers[3].address
#line 60 "sample/redirect_bpf.c"
         (r1, r2, r3, r4, r5);
#line 60 "sample/redirect_bpf.c"
    if ((authorize_connect4_helpers[3].tail_call) && (r0 == 0))
#line 60 "sample/redirect_bpf.c"
        return 0;
        // EBPF_OP_STXDW pc=58 dst=r10 src=r0 offset=-80 imm=0
#line 60 "sample/redirect_bpf.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r0;
    // EBPF_OP_MOV64_REG pc=59 dst=r1 src=r6 offset=0 imm=0
#line 61 "sample/redirect_bpf.c"
    r1 = r6;
    // EBPF_OP_CALL pc=60 dst=r0 src=r0 offset=0 imm=21
#line 61 "sample/redirect_bpf.c"
    r0 = authorize_connect4_helpers[4].address
#line 61 "sample/redirect_bpf.c"
         (r1, r2, r3, r4, r5);
#line 61 "sample/redirect_bpf.c"
    if ((authorize_connect4_helpers[4].tail_call) && (r0 == 0))
#line 61 "sample/redirect_bpf.c"
        return 0;
        // EBPF_OP_STXW pc=61 dst=r10 src=r0 offset=-68 imm=0
#line 61 "sample/redirect_bpf.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-68)) = (uint32_t)r0;
    // EBPF_OP_LDXW pc=62 dst=r1 src=r6 offset=24 imm=0
#line 62 "sample/redirect_bpf.c"
    r1 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(24));
    // EBPF_OP_STXW pc=63 dst=r10 src=r1 offset=-64 imm=0
#line 62 "sample/redirect_bpf.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint32_t)r1;
    // EBPF_OP_LDXH pc=64 dst=r1 src=r6 offset=40 imm=0
#line 63 "sample/redirect_bpf.c"
    r1 = *(uint16_t*)(uintptr_t)(r6 + OFFSET(40));
    // EBPF_OP_STXH pc=65 dst=r10 src=r1 offset=-60 imm=0
#line 63 "sample/redirect_bpf.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-60)) = (uint16_t)r1;
    // EBPF_OP_LDXH pc=66 dst=r1 src=r6 offset=20 imm=0
#line 65 "sample/redirect_bpf.c"
    r1 = *(uint16_t*)(uintptr_t)(r6 + OFFSET(20));
    // EBPF_OP_JNE_IMM pc=67 dst=r1 src=r0 offset=29 imm=0
#line 66 "sample/redirect_bpf.c"
    if (r1 != IMMEDIATE(0))
#line 66 "sample/redirect_bpf.c"
        goto label_2;
        // EBPF_OP_MOV64_REG pc=68 dst=r2 src=r10 offset=0 imm=0
#line 66 "sample/redirect_bpf.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=69 dst=r2 src=r0 offset=0 imm=-80
#line 67 "sample/redirect_bpf.c"
    r2 += IMMEDIATE(-80);
    // EBPF_OP_MOV64_REG pc=70 dst=r1 src=r6 offset=0 imm=0
#line 67 "sample/redirect_bpf.c"
    r1 = r6;
    // EBPF_OP_MOV64_IMM pc=71 dst=r3 src=r0 offset=0 imm=24
#line 67 "sample/redirect_bpf.c"
    r3 = IMMEDIATE(24);
    // EBPF_OP_CALL pc=72 dst=r0 src=r0 offset=0 imm=65537
#line 67 "sample/redirect_bpf.c"
    r0 = authorize_connect4_helpers[5].address
#line 67 "sample/redirect_bpf.c"
         (r1, r2, r3, r4, r5);
#line 67 "sample/redirect_bpf.c"
    if ((authorize_connect4_helpers[5].tail_call) && (r0 == 0))
#line 67 "sample/redirect_bpf.c"
        return 0;
        // EBPF_OP_JA pc=73 dst=r0 src=r0 offset=35 imm=0
#line 67 "sample/redirect_bpf.c"
    goto label_3;
label_1:
    // EBPF_OP_LDDW pc=74 dst=r1 src=r0 offset=0 imm=1769235301
#line 67 "sample/redirect_bpf.c"
    r1 = (uint64_t)13069273718350693;
    // EBPF_OP_STXDW pc=76 dst=r10 src=r1 offset=-40 imm=0
#line 95 "sample/redirect_bpf.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=77 dst=r1 src=r0 offset=0 imm=1914725736
#line 95 "sample/redirect_bpf.c"
    r1 = (uint64_t)8244230979747603816;
    // EBPF_OP_STXDW pc=79 dst=r10 src=r1 offset=-48 imm=0
#line 95 "sample/redirect_bpf.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=80 dst=r1 src=r0 offset=0 imm=1802706988
#line 95 "sample/redirect_bpf.c"
    r1 = (uint64_t)8367811705730965548;
    // EBPF_OP_STXDW pc=82 dst=r10 src=r1 offset=-56 imm=0
#line 95 "sample/redirect_bpf.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=83 dst=r1 src=r0 offset=0 imm=1696625523
#line 95 "sample/redirect_bpf.c"
    r1 = (uint64_t)8751185043426145139;
    // EBPF_OP_STXDW pc=85 dst=r10 src=r1 offset=-64 imm=0
#line 95 "sample/redirect_bpf.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=86 dst=r1 src=r0 offset=0 imm=1881174121
#line 95 "sample/redirect_bpf.c"
    r1 = (uint64_t)7305805557823205481;
    // EBPF_OP_STXDW pc=88 dst=r10 src=r1 offset=-72 imm=0
#line 95 "sample/redirect_bpf.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=89 dst=r1 src=r0 offset=0 imm=1853189958
#line 95 "sample/redirect_bpf.c"
    r1 = (uint64_t)7742567800102022982;
    // EBPF_OP_STXDW pc=91 dst=r10 src=r1 offset=-80 imm=0
#line 95 "sample/redirect_bpf.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=92 dst=r1 src=r10 offset=0 imm=0
#line 95 "sample/redirect_bpf.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=93 dst=r1 src=r0 offset=0 imm=-80
#line 95 "sample/redirect_bpf.c"
    r1 += IMMEDIATE(-80);
    // EBPF_OP_MOV64_IMM pc=94 dst=r2 src=r0 offset=0 imm=48
#line 95 "sample/redirect_bpf.c"
    r2 = IMMEDIATE(48);
    // EBPF_OP_CALL pc=95 dst=r0 src=r0 offset=0 imm=12
#line 95 "sample/redirect_bpf.c"
    r0 = authorize_connect4_helpers[6].address
#line 95 "sample/redirect_bpf.c"
         (r1, r2, r3, r4, r5);
#line 95 "sample/redirect_bpf.c"
    if ((authorize_connect4_helpers[6].tail_call) && (r0 == 0))
#line 95 "sample/redirect_bpf.c"
        return 0;
        // EBPF_OP_JA pc=96 dst=r0 src=r0 offset=16 imm=0
#line 95 "sample/redirect_bpf.c"
    goto label_4;
label_2:
    // EBPF_OP_STXDW pc=97 dst=r10 src=r9 offset=-8 imm=0
#line 70 "sample/redirect_bpf.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint64_t)r9;
    // EBPF_OP_LDXW pc=98 dst=r2 src=r6 offset=44 imm=0
#line 71 "sample/redirect_bpf.c"
    r2 = *(uint32_t*)(uintptr_t)(r6 + OFFSET(44));
    // EBPF_OP_STXH pc=99 dst=r10 src=r1 offset=-4 imm=0
#line 72 "sample/redirect_bpf.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint16_t)r1;
    // EBPF_OP_STXW pc=100 dst=r10 src=r2 offset=-8 imm=0
#line 71 "sample/redirect_bpf.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r2;
    // EBPF_OP_MOV64_REG pc=101 dst=r2 src=r10 offset=0 imm=0
#line 71 "sample/redirect_bpf.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=102 dst=r2 src=r0 offset=0 imm=-8
#line 70 "sample/redirect_bpf.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_REG pc=103 dst=r3 src=r10 offset=0 imm=0
#line 70 "sample/redirect_bpf.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=104 dst=r3 src=r0 offset=0 imm=-80
#line 70 "sample/redirect_bpf.c"
    r3 += IMMEDIATE(-80);
    // EBPF_OP_LDDW pc=105 dst=r1 src=r0 offset=0 imm=0
#line 73 "sample/redirect_bpf.c"
    r1 = POINTER(_maps[2].address);
    // EBPF_OP_MOV64_IMM pc=107 dst=r4 src=r0 offset=0 imm=0
#line 73 "sample/redirect_bpf.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=108 dst=r0 src=r0 offset=0 imm=2
#line 73 "sample/redirect_bpf.c"
    r0 = authorize_connect4_helpers[7].address
#line 73 "sample/redirect_bpf.c"
         (r1, r2, r3, r4, r5);
#line 73 "sample/redirect_bpf.c"
    if ((authorize_connect4_helpers[7].tail_call) && (r0 == 0))
#line 73 "sample/redirect_bpf.c"
        return 0;
label_3:
    // EBPF_OP_LDXW pc=109 dst=r1 src=r7 offset=0 imm=0
#line 99 "sample/redirect_bpf.c"
    r1 = *(uint32_t*)(uintptr_t)(r7 + OFFSET(0));
    // EBPF_OP_STXW pc=110 dst=r6 src=r1 offset=24 imm=0
#line 99 "sample/redirect_bpf.c"
    *(uint32_t*)(uintptr_t)(r6 + OFFSET(24)) = (uint32_t)r1;
    // EBPF_OP_LDXH pc=111 dst=r1 src=r7 offset=16 imm=0
#line 100 "sample/redirect_bpf.c"
    r1 = *(uint16_t*)(uintptr_t)(r7 + OFFSET(16));
    // EBPF_OP_STXH pc=112 dst=r6 src=r1 offset=40 imm=0
#line 100 "sample/redirect_bpf.c"
    *(uint16_t*)(uintptr_t)(r6 + OFFSET(40)) = (uint16_t)r1;
label_4:
    // EBPF_OP_MOV64_IMM pc=113 dst=r0 src=r0 offset=0 imm=1
#line 111 "sample/redirect_bpf.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=114 dst=r0 src=r0 offset=0 imm=0
#line 111 "sample/redirect_bpf.c"
    return r0;
#line 111 "sample/redirect_bpf.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        authorize_connect4,
        "cgroup~1",
        "cgroup/connect4",
        "authorize_connect4",
        authorize_connect4_maps,
        3,
        authorize_connect4_helpers,
        8,
        115,
        &authorize_connect4_program_type_guid,
        &authorize_connect4_attach_type_guid,
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
    version->minor = 13;
    version->revision = 0;
}

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = NULL;
    *count = 0;
}

metadata_table_t redirect_bpf_metadata_table = {
    sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version, _get_map_initial_values};
