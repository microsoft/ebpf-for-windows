// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from sockops.o

#define NO_CRT
#include "bpf2c.h"

#include <guiddef.h>
#include <wdm.h>
#include <wsk.h>

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
RTL_QUERY_REGISTRY_ROUTINE static _bpf2c_query_registry_routine;

#define metadata_table sockops##_metadata_table

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
         56,                // Size in bytes of a map key.
         4,                 // Size in bytes of a map value.
         1,                 // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         PIN_NONE,          // Pinning type for the map.
         0,                 // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "connection_map"},
    {NULL,
     {
         BPF_MAP_TYPE_RINGBUF, // Type of map.
         0,                    // Size in bytes of a map key.
         0,                    // Size in bytes of a map value.
         262144,               // Maximum number of entries allowed in the map.
         0,                    // Inner map index.
         PIN_NONE,             // Pinning type for the map.
         0,                    // Identifier for a map template.
         0,                    // The id of the inner map template.
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

static helper_function_entry_t connection_monitor_helpers[] = {
    {NULL, 1, "helper_id_1"},
    {NULL, 11, "helper_id_11"},
};

static GUID connection_monitor_program_type_guid = {
    0x43fb224d, 0x68f8, 0x46d6, {0xaa, 0x3f, 0xc8, 0x56, 0x51, 0x8c, 0xbb, 0x32}};
static GUID connection_monitor_attach_type_guid = {
    0x837d02cd, 0x3251, 0x4632, {0x8d, 0x94, 0x60, 0xd3, 0xb4, 0x57, 0x69, 0xf2}};
static uint16_t connection_monitor_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sockops")
static uint64_t
connection_monitor(void* context)
#line 67 "sample/sockops.c"
{
#line 67 "sample/sockops.c"
    // Prologue
#line 67 "sample/sockops.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 67 "sample/sockops.c"
    register uint64_t r0 = 0;
#line 67 "sample/sockops.c"
    register uint64_t r1 = 0;
#line 67 "sample/sockops.c"
    register uint64_t r2 = 0;
#line 67 "sample/sockops.c"
    register uint64_t r3 = 0;
#line 67 "sample/sockops.c"
    register uint64_t r4 = 0;
#line 67 "sample/sockops.c"
    register uint64_t r5 = 0;
#line 67 "sample/sockops.c"
    register uint64_t r6 = 0;
#line 67 "sample/sockops.c"
    register uint64_t r7 = 0;
#line 67 "sample/sockops.c"
    register uint64_t r8 = 0;
#line 67 "sample/sockops.c"
    register uint64_t r9 = 0;
#line 67 "sample/sockops.c"
    register uint64_t r10 = 0;

#line 67 "sample/sockops.c"
    r1 = (uintptr_t)context;
#line 67 "sample/sockops.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r7 src=r0 offset=0 imm=2
#line 67 "sample/sockops.c"
    r7 = IMMEDIATE(2);
    // EBPF_OP_MOV64_IMM pc=1 dst=r4 src=r0 offset=0 imm=1
#line 67 "sample/sockops.c"
    r4 = IMMEDIATE(1);
    // EBPF_OP_LDXW pc=2 dst=r2 src=r1 offset=0 imm=0
#line 72 "sample/sockops.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(0));
    // EBPF_OP_JEQ_IMM pc=3 dst=r2 src=r0 offset=8 imm=0
#line 72 "sample/sockops.c"
    if (r2 == IMMEDIATE(0))
#line 72 "sample/sockops.c"
        goto label_2;
        // EBPF_OP_JEQ_IMM pc=4 dst=r2 src=r0 offset=5 imm=2
#line 72 "sample/sockops.c"
    if (r2 == IMMEDIATE(2))
#line 72 "sample/sockops.c"
        goto label_1;
        // EBPF_OP_LDDW pc=5 dst=r6 src=r0 offset=0 imm=-1
#line 72 "sample/sockops.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JNE_IMM pc=7 dst=r2 src=r0 offset=217 imm=1
#line 72 "sample/sockops.c"
    if (r2 != IMMEDIATE(1))
#line 72 "sample/sockops.c"
        goto label_13;
        // EBPF_OP_MOV64_IMM pc=8 dst=r4 src=r0 offset=0 imm=0
#line 72 "sample/sockops.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_JA pc=9 dst=r0 src=r0 offset=2 imm=0
#line 72 "sample/sockops.c"
    goto label_2;
label_1:
    // EBPF_OP_MOV64_IMM pc=10 dst=r4 src=r0 offset=0 imm=0
#line 72 "sample/sockops.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_MOV64_IMM pc=11 dst=r7 src=r0 offset=0 imm=0
#line 72 "sample/sockops.c"
    r7 = IMMEDIATE(0);
label_2:
    // EBPF_OP_LDXW pc=12 dst=r2 src=r1 offset=4 imm=0
#line 89 "sample/sockops.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(4));
    // EBPF_OP_JNE_IMM pc=13 dst=r2 src=r0 offset=50 imm=2
#line 89 "sample/sockops.c"
    if (r2 != IMMEDIATE(2))
#line 89 "sample/sockops.c"
        goto label_7;
        // EBPF_OP_MOV64_IMM pc=14 dst=r6 src=r0 offset=0 imm=0
#line 89 "sample/sockops.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=15 dst=r10 src=r6 offset=-8 imm=0
#line 22 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint64_t)r6;
    // EBPF_OP_STXDW pc=16 dst=r10 src=r6 offset=-16 imm=0
#line 22 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r6;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r6 offset=-24 imm=0
#line 22 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r6;
    // EBPF_OP_STXDW pc=18 dst=r10 src=r6 offset=-32 imm=0
#line 22 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r6;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r6 offset=-40 imm=0
#line 22 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r6;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r6 offset=-48 imm=0
#line 22 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r6;
    // EBPF_OP_STXDW pc=21 dst=r10 src=r6 offset=-56 imm=0
#line 22 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r6;
    // EBPF_OP_STXDW pc=22 dst=r10 src=r6 offset=-64 imm=0
#line 22 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r6;
    // EBPF_OP_MOV64_IMM pc=23 dst=r2 src=r0 offset=0 imm=28
#line 22 "sample/sockops.c"
    r2 = IMMEDIATE(28);
    // EBPF_OP_MOV64_IMM pc=24 dst=r5 src=r0 offset=0 imm=8
#line 24 "sample/sockops.c"
    r5 = IMMEDIATE(8);
    // EBPF_OP_JNE_IMM pc=25 dst=r4 src=r0 offset=1 imm=0
#line 24 "sample/sockops.c"
    if (r4 != IMMEDIATE(0))
#line 24 "sample/sockops.c"
        goto label_3;
        // EBPF_OP_MOV64_IMM pc=26 dst=r5 src=r0 offset=0 imm=28
#line 24 "sample/sockops.c"
    r5 = IMMEDIATE(28);
label_3:
    // EBPF_OP_MOV64_REG pc=27 dst=r3 src=r1 offset=0 imm=0
#line 24 "sample/sockops.c"
    r3 = r1;
    // EBPF_OP_ADD64_REG pc=28 dst=r3 src=r5 offset=0 imm=0
#line 24 "sample/sockops.c"
    r3 += r5;
    // EBPF_OP_LDXW pc=29 dst=r3 src=r3 offset=0 imm=0
#line 24 "sample/sockops.c"
    r3 = *(uint32_t*)(uintptr_t)(r3 + OFFSET(0));
    // EBPF_OP_STXW pc=30 dst=r10 src=r3 offset=-64 imm=0
#line 24 "sample/sockops.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint32_t)r3;
    // EBPF_OP_MOV64_IMM pc=31 dst=r0 src=r0 offset=0 imm=44
#line 24 "sample/sockops.c"
    r0 = IMMEDIATE(44);
    // EBPF_OP_MOV64_IMM pc=32 dst=r3 src=r0 offset=0 imm=24
#line 25 "sample/sockops.c"
    r3 = IMMEDIATE(24);
    // EBPF_OP_JNE_IMM pc=33 dst=r4 src=r0 offset=1 imm=0
#line 25 "sample/sockops.c"
    if (r4 != IMMEDIATE(0))
#line 25 "sample/sockops.c"
        goto label_4;
        // EBPF_OP_MOV64_IMM pc=34 dst=r3 src=r0 offset=0 imm=44
#line 25 "sample/sockops.c"
    r3 = IMMEDIATE(44);
label_4:
    // EBPF_OP_MOV64_REG pc=35 dst=r5 src=r1 offset=0 imm=0
#line 25 "sample/sockops.c"
    r5 = r1;
    // EBPF_OP_ADD64_REG pc=36 dst=r5 src=r3 offset=0 imm=0
#line 25 "sample/sockops.c"
    r5 += r3;
    // EBPF_OP_LDXW pc=37 dst=r3 src=r5 offset=0 imm=0
#line 25 "sample/sockops.c"
    r3 = *(uint32_t*)(uintptr_t)(r5 + OFFSET(0));
    // EBPF_OP_STXH pc=38 dst=r10 src=r3 offset=-48 imm=0
#line 25 "sample/sockops.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint16_t)r3;
    // EBPF_OP_JNE_IMM pc=39 dst=r4 src=r0 offset=1 imm=0
#line 27 "sample/sockops.c"
    if (r4 != IMMEDIATE(0))
#line 27 "sample/sockops.c"
        goto label_5;
        // EBPF_OP_MOV64_IMM pc=40 dst=r0 src=r0 offset=0 imm=24
#line 27 "sample/sockops.c"
    r0 = IMMEDIATE(24);
label_5:
    // EBPF_OP_JNE_IMM pc=41 dst=r4 src=r0 offset=1 imm=0
#line 26 "sample/sockops.c"
    if (r4 != IMMEDIATE(0))
#line 26 "sample/sockops.c"
        goto label_6;
        // EBPF_OP_MOV64_IMM pc=42 dst=r2 src=r0 offset=0 imm=8
#line 26 "sample/sockops.c"
    r2 = IMMEDIATE(8);
label_6:
    // EBPF_OP_OR64_REG pc=43 dst=r7 src=r4 offset=0 imm=0
#line 30 "sample/sockops.c"
    r7 |= r4;
    // EBPF_OP_MOV64_REG pc=44 dst=r3 src=r1 offset=0 imm=0
#line 26 "sample/sockops.c"
    r3 = r1;
    // EBPF_OP_ADD64_REG pc=45 dst=r3 src=r2 offset=0 imm=0
#line 26 "sample/sockops.c"
    r3 += r2;
    // EBPF_OP_LDXW pc=46 dst=r2 src=r3 offset=0 imm=0
#line 26 "sample/sockops.c"
    r2 = *(uint32_t*)(uintptr_t)(r3 + OFFSET(0));
    // EBPF_OP_STXW pc=47 dst=r10 src=r2 offset=-44 imm=0
#line 26 "sample/sockops.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-44)) = (uint32_t)r2;
    // EBPF_OP_MOV64_REG pc=48 dst=r2 src=r1 offset=0 imm=0
#line 27 "sample/sockops.c"
    r2 = r1;
    // EBPF_OP_ADD64_REG pc=49 dst=r2 src=r0 offset=0 imm=0
#line 27 "sample/sockops.c"
    r2 += r0;
    // EBPF_OP_LDXW pc=50 dst=r2 src=r2 offset=0 imm=0
#line 27 "sample/sockops.c"
    r2 = *(uint32_t*)(uintptr_t)(r2 + OFFSET(0));
    // EBPF_OP_STXH pc=51 dst=r10 src=r2 offset=-28 imm=0
#line 27 "sample/sockops.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-28)) = (uint16_t)r2;
    // EBPF_OP_LDXB pc=52 dst=r2 src=r1 offset=48 imm=0
#line 28 "sample/sockops.c"
    r2 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(48));
    // EBPF_OP_STXW pc=53 dst=r10 src=r2 offset=-24 imm=0
#line 28 "sample/sockops.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r2;
    // EBPF_OP_LDXDW pc=54 dst=r1 src=r1 offset=56 imm=0
#line 29 "sample/sockops.c"
    r1 = *(uint64_t*)(uintptr_t)(r1 + OFFSET(56));
    // EBPF_OP_STXB pc=55 dst=r10 src=r7 offset=-8 imm=0
#line 31 "sample/sockops.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r7;
    // EBPF_OP_STXDW pc=56 dst=r10 src=r1 offset=-16 imm=0
#line 29 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=57 dst=r2 src=r10 offset=0 imm=0
#line 29 "sample/sockops.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=58 dst=r2 src=r0 offset=0 imm=-64
#line 30 "sample/sockops.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_LDDW pc=59 dst=r1 src=r0 offset=0 imm=0
#line 33 "sample/sockops.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=61 dst=r0 src=r0 offset=0 imm=1
#line 33 "sample/sockops.c"
    r0 = connection_monitor_helpers[0].address
#line 33 "sample/sockops.c"
         (r1, r2, r3, r4, r5);
#line 33 "sample/sockops.c"
    if ((connection_monitor_helpers[0].tail_call) && (r0 == 0))
#line 33 "sample/sockops.c"
        return 0;
        // EBPF_OP_JEQ_IMM pc=62 dst=r0 src=r0 offset=162 imm=0
#line 33 "sample/sockops.c"
    if (r0 == IMMEDIATE(0))
#line 33 "sample/sockops.c"
        goto label_13;
        // EBPF_OP_JA pc=63 dst=r0 src=r0 offset=153 imm=0
#line 33 "sample/sockops.c"
    goto label_12;
label_7:
    // EBPF_OP_STXDW pc=64 dst=r10 src=r7 offset=-72 imm=0
#line 33 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r7;
    // EBPF_OP_MOV64_IMM pc=65 dst=r2 src=r0 offset=0 imm=0
#line 33 "sample/sockops.c"
    r2 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=66 dst=r10 src=r2 offset=-8 imm=0
#line 48 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=67 dst=r10 src=r2 offset=-16 imm=0
#line 48 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=68 dst=r10 src=r2 offset=-24 imm=0
#line 48 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=69 dst=r10 src=r2 offset=-32 imm=0
#line 48 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=70 dst=r10 src=r2 offset=-40 imm=0
#line 48 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r2;
    // EBPF_OP_STXDW pc=71 dst=r10 src=r2 offset=-48 imm=0
#line 48 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r2;
    // EBPF_OP_MOV64_REG pc=72 dst=r3 src=r1 offset=0 imm=0
#line 47 "sample/sockops.c"
    r3 = r1;
    // EBPF_OP_ADD64_IMM pc=73 dst=r3 src=r0 offset=0 imm=28
#line 47 "sample/sockops.c"
    r3 += IMMEDIATE(28);
    // EBPF_OP_STXDW pc=74 dst=r10 src=r1 offset=-96 imm=0
#line 47 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=75 dst=r0 src=r1 offset=0 imm=0
#line 47 "sample/sockops.c"
    r0 = r1;
    // EBPF_OP_ADD64_IMM pc=76 dst=r0 src=r0 offset=0 imm=8
#line 47 "sample/sockops.c"
    r0 += IMMEDIATE(8);
    // EBPF_OP_STXDW pc=77 dst=r10 src=r0 offset=-120 imm=0
#line 47 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120)) = (uint64_t)r0;
    // EBPF_OP_JNE_IMM pc=78 dst=r4 src=r0 offset=1 imm=0
#line 47 "sample/sockops.c"
    if (r4 != IMMEDIATE(0))
#line 47 "sample/sockops.c"
        goto label_8;
        // EBPF_OP_MOV64_REG pc=79 dst=r0 src=r3 offset=0 imm=0
#line 47 "sample/sockops.c"
    r0 = r3;
label_8:
    // EBPF_OP_LDXB pc=80 dst=r2 src=r0 offset=13 imm=0
#line 48 "sample/sockops.c"
    r2 = *(uint8_t*)(uintptr_t)(r0 + OFFSET(13));
    // EBPF_OP_LSH64_IMM pc=81 dst=r2 src=r0 offset=0 imm=8
#line 48 "sample/sockops.c"
    r2 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=82 dst=r1 src=r0 offset=12 imm=0
#line 48 "sample/sockops.c"
    r1 = *(uint8_t*)(uintptr_t)(r0 + OFFSET(12));
    // EBPF_OP_STXDW pc=83 dst=r10 src=r1 offset=-80 imm=0
#line 48 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDXB pc=84 dst=r8 src=r0 offset=15 imm=0
#line 48 "sample/sockops.c"
    r8 = *(uint8_t*)(uintptr_t)(r0 + OFFSET(15));
    // EBPF_OP_LSH64_IMM pc=85 dst=r8 src=r0 offset=0 imm=8
#line 48 "sample/sockops.c"
    r8 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=86 dst=r5 src=r0 offset=14 imm=0
#line 48 "sample/sockops.c"
    r5 = *(uint8_t*)(uintptr_t)(r0 + OFFSET(14));
    // EBPF_OP_OR64_REG pc=87 dst=r8 src=r5 offset=0 imm=0
#line 48 "sample/sockops.c"
    r8 |= r5;
    // EBPF_OP_LDXB pc=88 dst=r6 src=r0 offset=9 imm=0
#line 48 "sample/sockops.c"
    r6 = *(uint8_t*)(uintptr_t)(r0 + OFFSET(9));
    // EBPF_OP_LSH64_IMM pc=89 dst=r6 src=r0 offset=0 imm=8
#line 48 "sample/sockops.c"
    r6 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=90 dst=r1 src=r0 offset=8 imm=0
#line 48 "sample/sockops.c"
    r1 = *(uint8_t*)(uintptr_t)(r0 + OFFSET(8));
    // EBPF_OP_STXDW pc=91 dst=r10 src=r1 offset=-88 imm=0
#line 48 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDXB pc=92 dst=r9 src=r0 offset=11 imm=0
#line 48 "sample/sockops.c"
    r9 = *(uint8_t*)(uintptr_t)(r0 + OFFSET(11));
    // EBPF_OP_LSH64_IMM pc=93 dst=r9 src=r0 offset=0 imm=8
#line 48 "sample/sockops.c"
    r9 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=94 dst=r5 src=r0 offset=10 imm=0
#line 48 "sample/sockops.c"
    r5 = *(uint8_t*)(uintptr_t)(r0 + OFFSET(10));
    // EBPF_OP_OR64_REG pc=95 dst=r9 src=r5 offset=0 imm=0
#line 48 "sample/sockops.c"
    r9 |= r5;
    // EBPF_OP_LDXB pc=96 dst=r5 src=r0 offset=1 imm=0
#line 48 "sample/sockops.c"
    r5 = *(uint8_t*)(uintptr_t)(r0 + OFFSET(1));
    // EBPF_OP_LDXB pc=97 dst=r7 src=r0 offset=0 imm=0
#line 48 "sample/sockops.c"
    r7 = *(uint8_t*)(uintptr_t)(r0 + OFFSET(0));
    // EBPF_OP_STXDW pc=98 dst=r10 src=r7 offset=-104 imm=0
#line 48 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r7;
    // EBPF_OP_LDXB pc=99 dst=r7 src=r0 offset=3 imm=0
#line 48 "sample/sockops.c"
    r7 = *(uint8_t*)(uintptr_t)(r0 + OFFSET(3));
    // EBPF_OP_LDXB pc=100 dst=r1 src=r0 offset=2 imm=0
#line 48 "sample/sockops.c"
    r1 = *(uint8_t*)(uintptr_t)(r0 + OFFSET(2));
    // EBPF_OP_STXDW pc=101 dst=r10 src=r1 offset=-112 imm=0
#line 49 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_JNE_IMM pc=102 dst=r4 src=r0 offset=1 imm=0
#line 49 "sample/sockops.c"
    if (r4 != IMMEDIATE(0))
#line 49 "sample/sockops.c"
        goto label_9;
        // EBPF_OP_LDXDW pc=103 dst=r3 src=r10 offset=-120 imm=0
#line 49 "sample/sockops.c"
    r3 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-120));
label_9:
    // EBPF_OP_LDXDW pc=104 dst=r1 src=r10 offset=-80 imm=0
#line 49 "sample/sockops.c"
    r1 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80));
    // EBPF_OP_OR64_REG pc=105 dst=r2 src=r1 offset=0 imm=0
#line 49 "sample/sockops.c"
    r2 |= r1;
    // EBPF_OP_LDXDW pc=106 dst=r1 src=r10 offset=-88 imm=0
#line 49 "sample/sockops.c"
    r1 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88));
    // EBPF_OP_OR64_REG pc=107 dst=r6 src=r1 offset=0 imm=0
#line 49 "sample/sockops.c"
    r6 |= r1;
    // EBPF_OP_LSH64_IMM pc=108 dst=r9 src=r0 offset=0 imm=16
#line 49 "sample/sockops.c"
    r9 <<= IMMEDIATE(16);
    // EBPF_OP_LSH64_IMM pc=109 dst=r8 src=r0 offset=0 imm=16
#line 49 "sample/sockops.c"
    r8 <<= IMMEDIATE(16);
    // EBPF_OP_LSH64_IMM pc=110 dst=r5 src=r0 offset=0 imm=8
#line 49 "sample/sockops.c"
    r5 <<= IMMEDIATE(8);
    // EBPF_OP_LSH64_IMM pc=111 dst=r7 src=r0 offset=0 imm=8
#line 49 "sample/sockops.c"
    r7 <<= IMMEDIATE(8);
    // EBPF_OP_MOV64_IMM pc=112 dst=r1 src=r0 offset=0 imm=44
#line 49 "sample/sockops.c"
    r1 = IMMEDIATE(44);
    // EBPF_OP_STXDW pc=113 dst=r10 src=r1 offset=-88 imm=0
#line 49 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_MOV64_IMM pc=114 dst=r1 src=r0 offset=0 imm=24
#line 49 "sample/sockops.c"
    r1 = IMMEDIATE(24);
    // EBPF_OP_STXDW pc=115 dst=r10 src=r1 offset=-80 imm=0
#line 49 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_JNE_IMM pc=116 dst=r4 src=r0 offset=2 imm=0
#line 49 "sample/sockops.c"
    if (r4 != IMMEDIATE(0))
#line 49 "sample/sockops.c"
        goto label_10;
        // EBPF_OP_MOV64_IMM pc=117 dst=r1 src=r0 offset=0 imm=44
#line 49 "sample/sockops.c"
    r1 = IMMEDIATE(44);
    // EBPF_OP_STXDW pc=118 dst=r10 src=r1 offset=-80 imm=0
#line 49 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
label_10:
    // EBPF_OP_OR64_REG pc=119 dst=r9 src=r6 offset=0 imm=0
#line 49 "sample/sockops.c"
    r9 |= r6;
    // EBPF_OP_OR64_REG pc=120 dst=r8 src=r2 offset=0 imm=0
#line 49 "sample/sockops.c"
    r8 |= r2;
    // EBPF_OP_LDXDW pc=121 dst=r1 src=r10 offset=-104 imm=0
#line 49 "sample/sockops.c"
    r1 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104));
    // EBPF_OP_OR64_REG pc=122 dst=r5 src=r1 offset=0 imm=0
#line 49 "sample/sockops.c"
    r5 |= r1;
    // EBPF_OP_LDXDW pc=123 dst=r1 src=r10 offset=-112 imm=0
#line 49 "sample/sockops.c"
    r1 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112));
    // EBPF_OP_OR64_REG pc=124 dst=r7 src=r1 offset=0 imm=0
#line 49 "sample/sockops.c"
    r7 |= r1;
    // EBPF_OP_JNE_IMM pc=125 dst=r4 src=r0 offset=2 imm=0
#line 52 "sample/sockops.c"
    if (r4 != IMMEDIATE(0))
#line 52 "sample/sockops.c"
        goto label_11;
        // EBPF_OP_MOV64_IMM pc=126 dst=r1 src=r0 offset=0 imm=24
#line 52 "sample/sockops.c"
    r1 = IMMEDIATE(24);
    // EBPF_OP_STXDW pc=127 dst=r10 src=r1 offset=-88 imm=0
#line 52 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
label_11:
    // EBPF_OP_LDXDW pc=128 dst=r2 src=r10 offset=-72 imm=0
#line 52 "sample/sockops.c"
    r2 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72));
    // EBPF_OP_OR64_REG pc=129 dst=r2 src=r4 offset=0 imm=0
#line 55 "sample/sockops.c"
    r2 |= r4;
    // EBPF_OP_STXDW pc=130 dst=r10 src=r2 offset=-72 imm=0
#line 55 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r2;
    // EBPF_OP_LSH64_IMM pc=131 dst=r8 src=r0 offset=0 imm=32
#line 48 "sample/sockops.c"
    r8 <<= IMMEDIATE(32);
    // EBPF_OP_OR64_REG pc=132 dst=r8 src=r9 offset=0 imm=0
#line 48 "sample/sockops.c"
    r8 |= r9;
    // EBPF_OP_STXDW pc=133 dst=r10 src=r8 offset=-56 imm=0
#line 48 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r8;
    // EBPF_OP_LSH64_IMM pc=134 dst=r7 src=r0 offset=0 imm=16
#line 48 "sample/sockops.c"
    r7 <<= IMMEDIATE(16);
    // EBPF_OP_OR64_REG pc=135 dst=r7 src=r5 offset=0 imm=0
#line 48 "sample/sockops.c"
    r7 |= r5;
    // EBPF_OP_LDXB pc=136 dst=r1 src=r0 offset=5 imm=0
#line 48 "sample/sockops.c"
    r1 = *(uint8_t*)(uintptr_t)(r0 + OFFSET(5));
    // EBPF_OP_LSH64_IMM pc=137 dst=r1 src=r0 offset=0 imm=8
#line 48 "sample/sockops.c"
    r1 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=138 dst=r2 src=r0 offset=4 imm=0
#line 48 "sample/sockops.c"
    r2 = *(uint8_t*)(uintptr_t)(r0 + OFFSET(4));
    // EBPF_OP_OR64_REG pc=139 dst=r1 src=r2 offset=0 imm=0
#line 48 "sample/sockops.c"
    r1 |= r2;
    // EBPF_OP_LDXB pc=140 dst=r2 src=r0 offset=6 imm=0
#line 48 "sample/sockops.c"
    r2 = *(uint8_t*)(uintptr_t)(r0 + OFFSET(6));
    // EBPF_OP_LDXB pc=141 dst=r4 src=r0 offset=7 imm=0
#line 48 "sample/sockops.c"
    r4 = *(uint8_t*)(uintptr_t)(r0 + OFFSET(7));
    // EBPF_OP_LSH64_IMM pc=142 dst=r4 src=r0 offset=0 imm=8
#line 48 "sample/sockops.c"
    r4 <<= IMMEDIATE(8);
    // EBPF_OP_OR64_REG pc=143 dst=r4 src=r2 offset=0 imm=0
#line 48 "sample/sockops.c"
    r4 |= r2;
    // EBPF_OP_LSH64_IMM pc=144 dst=r4 src=r0 offset=0 imm=16
#line 48 "sample/sockops.c"
    r4 <<= IMMEDIATE(16);
    // EBPF_OP_OR64_REG pc=145 dst=r4 src=r1 offset=0 imm=0
#line 48 "sample/sockops.c"
    r4 |= r1;
    // EBPF_OP_LSH64_IMM pc=146 dst=r4 src=r0 offset=0 imm=32
#line 48 "sample/sockops.c"
    r4 <<= IMMEDIATE(32);
    // EBPF_OP_OR64_REG pc=147 dst=r4 src=r7 offset=0 imm=0
#line 48 "sample/sockops.c"
    r4 |= r7;
    // EBPF_OP_STXDW pc=148 dst=r10 src=r4 offset=-64 imm=0
#line 48 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r4;
    // EBPF_OP_LDXDW pc=149 dst=r6 src=r10 offset=-96 imm=0
#line 48 "sample/sockops.c"
    r6 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96));
    // EBPF_OP_MOV64_REG pc=150 dst=r1 src=r6 offset=0 imm=0
#line 49 "sample/sockops.c"
    r1 = r6;
    // EBPF_OP_LDXDW pc=151 dst=r2 src=r10 offset=-80 imm=0
#line 49 "sample/sockops.c"
    r2 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80));
    // EBPF_OP_ADD64_REG pc=152 dst=r1 src=r2 offset=0 imm=0
#line 49 "sample/sockops.c"
    r1 += r2;
    // EBPF_OP_LDXW pc=153 dst=r1 src=r1 offset=0 imm=0
#line 49 "sample/sockops.c"
    r1 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(0));
    // EBPF_OP_STXH pc=154 dst=r10 src=r1 offset=-48 imm=0
#line 49 "sample/sockops.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint16_t)r1;
    // EBPF_OP_LDXB pc=155 dst=r4 src=r3 offset=13 imm=0
#line 51 "sample/sockops.c"
    r4 = *(uint8_t*)(uintptr_t)(r3 + OFFSET(13));
    // EBPF_OP_LSH64_IMM pc=156 dst=r4 src=r0 offset=0 imm=8
#line 51 "sample/sockops.c"
    r4 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=157 dst=r1 src=r3 offset=12 imm=0
#line 51 "sample/sockops.c"
    r1 = *(uint8_t*)(uintptr_t)(r3 + OFFSET(12));
    // EBPF_OP_OR64_REG pc=158 dst=r4 src=r1 offset=0 imm=0
#line 51 "sample/sockops.c"
    r4 |= r1;
    // EBPF_OP_LDXB pc=159 dst=r2 src=r3 offset=15 imm=0
#line 51 "sample/sockops.c"
    r2 = *(uint8_t*)(uintptr_t)(r3 + OFFSET(15));
    // EBPF_OP_LSH64_IMM pc=160 dst=r2 src=r0 offset=0 imm=8
#line 51 "sample/sockops.c"
    r2 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=161 dst=r1 src=r3 offset=14 imm=0
#line 51 "sample/sockops.c"
    r1 = *(uint8_t*)(uintptr_t)(r3 + OFFSET(14));
    // EBPF_OP_OR64_REG pc=162 dst=r2 src=r1 offset=0 imm=0
#line 51 "sample/sockops.c"
    r2 |= r1;
    // EBPF_OP_LDXB pc=163 dst=r5 src=r3 offset=1 imm=0
#line 51 "sample/sockops.c"
    r5 = *(uint8_t*)(uintptr_t)(r3 + OFFSET(1));
    // EBPF_OP_LSH64_IMM pc=164 dst=r5 src=r0 offset=0 imm=8
#line 51 "sample/sockops.c"
    r5 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=165 dst=r1 src=r3 offset=0 imm=0
#line 51 "sample/sockops.c"
    r1 = *(uint8_t*)(uintptr_t)(r3 + OFFSET(0));
    // EBPF_OP_OR64_REG pc=166 dst=r5 src=r1 offset=0 imm=0
#line 51 "sample/sockops.c"
    r5 |= r1;
    // EBPF_OP_LDXB pc=167 dst=r1 src=r3 offset=3 imm=0
#line 51 "sample/sockops.c"
    r1 = *(uint8_t*)(uintptr_t)(r3 + OFFSET(3));
    // EBPF_OP_LSH64_IMM pc=168 dst=r1 src=r0 offset=0 imm=8
#line 51 "sample/sockops.c"
    r1 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=169 dst=r0 src=r3 offset=2 imm=0
#line 51 "sample/sockops.c"
    r0 = *(uint8_t*)(uintptr_t)(r3 + OFFSET(2));
    // EBPF_OP_OR64_REG pc=170 dst=r1 src=r0 offset=0 imm=0
#line 51 "sample/sockops.c"
    r1 |= r0;
    // EBPF_OP_LSH64_IMM pc=171 dst=r1 src=r0 offset=0 imm=16
#line 51 "sample/sockops.c"
    r1 <<= IMMEDIATE(16);
    // EBPF_OP_OR64_REG pc=172 dst=r1 src=r5 offset=0 imm=0
#line 51 "sample/sockops.c"
    r1 |= r5;
    // EBPF_OP_LSH64_IMM pc=173 dst=r2 src=r0 offset=0 imm=16
#line 51 "sample/sockops.c"
    r2 <<= IMMEDIATE(16);
    // EBPF_OP_OR64_REG pc=174 dst=r2 src=r4 offset=0 imm=0
#line 51 "sample/sockops.c"
    r2 |= r4;
    // EBPF_OP_LDXB pc=175 dst=r4 src=r3 offset=9 imm=0
#line 51 "sample/sockops.c"
    r4 = *(uint8_t*)(uintptr_t)(r3 + OFFSET(9));
    // EBPF_OP_LSH64_IMM pc=176 dst=r4 src=r0 offset=0 imm=8
#line 51 "sample/sockops.c"
    r4 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=177 dst=r5 src=r3 offset=8 imm=0
#line 51 "sample/sockops.c"
    r5 = *(uint8_t*)(uintptr_t)(r3 + OFFSET(8));
    // EBPF_OP_OR64_REG pc=178 dst=r4 src=r5 offset=0 imm=0
#line 51 "sample/sockops.c"
    r4 |= r5;
    // EBPF_OP_LDXB pc=179 dst=r5 src=r3 offset=11 imm=0
#line 51 "sample/sockops.c"
    r5 = *(uint8_t*)(uintptr_t)(r3 + OFFSET(11));
    // EBPF_OP_LSH64_IMM pc=180 dst=r5 src=r0 offset=0 imm=8
#line 51 "sample/sockops.c"
    r5 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=181 dst=r0 src=r3 offset=10 imm=0
#line 51 "sample/sockops.c"
    r0 = *(uint8_t*)(uintptr_t)(r3 + OFFSET(10));
    // EBPF_OP_OR64_REG pc=182 dst=r5 src=r0 offset=0 imm=0
#line 51 "sample/sockops.c"
    r5 |= r0;
    // EBPF_OP_LSH64_IMM pc=183 dst=r5 src=r0 offset=0 imm=16
#line 51 "sample/sockops.c"
    r5 <<= IMMEDIATE(16);
    // EBPF_OP_OR64_REG pc=184 dst=r5 src=r4 offset=0 imm=0
#line 51 "sample/sockops.c"
    r5 |= r4;
    // EBPF_OP_STXW pc=185 dst=r10 src=r5 offset=-36 imm=0
#line 51 "sample/sockops.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-36)) = (uint32_t)r5;
    // EBPF_OP_STXW pc=186 dst=r10 src=r2 offset=-32 imm=0
#line 51 "sample/sockops.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint32_t)r2;
    // EBPF_OP_STXW pc=187 dst=r10 src=r1 offset=-44 imm=0
#line 51 "sample/sockops.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-44)) = (uint32_t)r1;
    // EBPF_OP_LDXB pc=188 dst=r1 src=r3 offset=5 imm=0
#line 51 "sample/sockops.c"
    r1 = *(uint8_t*)(uintptr_t)(r3 + OFFSET(5));
    // EBPF_OP_LSH64_IMM pc=189 dst=r1 src=r0 offset=0 imm=8
#line 51 "sample/sockops.c"
    r1 <<= IMMEDIATE(8);
    // EBPF_OP_LDXB pc=190 dst=r2 src=r3 offset=4 imm=0
#line 51 "sample/sockops.c"
    r2 = *(uint8_t*)(uintptr_t)(r3 + OFFSET(4));
    // EBPF_OP_OR64_REG pc=191 dst=r1 src=r2 offset=0 imm=0
#line 51 "sample/sockops.c"
    r1 |= r2;
    // EBPF_OP_LDXB pc=192 dst=r2 src=r3 offset=6 imm=0
#line 51 "sample/sockops.c"
    r2 = *(uint8_t*)(uintptr_t)(r3 + OFFSET(6));
    // EBPF_OP_LDXB pc=193 dst=r3 src=r3 offset=7 imm=0
#line 51 "sample/sockops.c"
    r3 = *(uint8_t*)(uintptr_t)(r3 + OFFSET(7));
    // EBPF_OP_LSH64_IMM pc=194 dst=r3 src=r0 offset=0 imm=8
#line 51 "sample/sockops.c"
    r3 <<= IMMEDIATE(8);
    // EBPF_OP_OR64_REG pc=195 dst=r3 src=r2 offset=0 imm=0
#line 51 "sample/sockops.c"
    r3 |= r2;
    // EBPF_OP_LSH64_IMM pc=196 dst=r3 src=r0 offset=0 imm=16
#line 51 "sample/sockops.c"
    r3 <<= IMMEDIATE(16);
    // EBPF_OP_OR64_REG pc=197 dst=r3 src=r1 offset=0 imm=0
#line 51 "sample/sockops.c"
    r3 |= r1;
    // EBPF_OP_STXW pc=198 dst=r10 src=r3 offset=-40 imm=0
#line 51 "sample/sockops.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint32_t)r3;
    // EBPF_OP_MOV64_REG pc=199 dst=r1 src=r6 offset=0 imm=0
#line 52 "sample/sockops.c"
    r1 = r6;
    // EBPF_OP_LDXDW pc=200 dst=r2 src=r10 offset=-88 imm=0
#line 52 "sample/sockops.c"
    r2 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88));
    // EBPF_OP_ADD64_REG pc=201 dst=r1 src=r2 offset=0 imm=0
#line 52 "sample/sockops.c"
    r1 += r2;
    // EBPF_OP_LDXW pc=202 dst=r1 src=r1 offset=0 imm=0
#line 52 "sample/sockops.c"
    r1 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(0));
    // EBPF_OP_STXH pc=203 dst=r10 src=r1 offset=-28 imm=0
#line 52 "sample/sockops.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-28)) = (uint16_t)r1;
    // EBPF_OP_LDXB pc=204 dst=r1 src=r6 offset=48 imm=0
#line 53 "sample/sockops.c"
    r1 = *(uint8_t*)(uintptr_t)(r6 + OFFSET(48));
    // EBPF_OP_STXW pc=205 dst=r10 src=r1 offset=-24 imm=0
#line 53 "sample/sockops.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r1;
    // EBPF_OP_LDXDW pc=206 dst=r1 src=r6 offset=56 imm=0
#line 54 "sample/sockops.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(56));
    // EBPF_OP_LDXDW pc=207 dst=r2 src=r10 offset=-72 imm=0
#line 56 "sample/sockops.c"
    r2 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72));
    // EBPF_OP_STXB pc=208 dst=r10 src=r2 offset=-8 imm=0
#line 56 "sample/sockops.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r2;
    // EBPF_OP_STXDW pc=209 dst=r10 src=r1 offset=-16 imm=0
#line 54 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=210 dst=r2 src=r10 offset=0 imm=0
#line 54 "sample/sockops.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=211 dst=r2 src=r0 offset=0 imm=-64
#line 55 "sample/sockops.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_LDDW pc=212 dst=r1 src=r0 offset=0 imm=0
#line 58 "sample/sockops.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=214 dst=r0 src=r0 offset=0 imm=1
#line 58 "sample/sockops.c"
    r0 = connection_monitor_helpers[0].address
#line 58 "sample/sockops.c"
         (r1, r2, r3, r4, r5);
#line 58 "sample/sockops.c"
    if ((connection_monitor_helpers[0].tail_call) && (r0 == 0))
#line 58 "sample/sockops.c"
        return 0;
        // EBPF_OP_MOV64_IMM pc=215 dst=r6 src=r0 offset=0 imm=0
#line 58 "sample/sockops.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_JEQ_IMM pc=216 dst=r0 src=r0 offset=8 imm=0
#line 58 "sample/sockops.c"
    if (r0 == IMMEDIATE(0))
#line 58 "sample/sockops.c"
        goto label_13;
label_12:
    // EBPF_OP_MOV64_REG pc=217 dst=r2 src=r10 offset=0 imm=0
#line 58 "sample/sockops.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=218 dst=r2 src=r0 offset=0 imm=-64
#line 58 "sample/sockops.c"
    r2 += IMMEDIATE(-64);
    // EBPF_OP_LDDW pc=219 dst=r1 src=r0 offset=0 imm=0
#line 58 "sample/sockops.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_MOV64_IMM pc=221 dst=r3 src=r0 offset=0 imm=64
#line 58 "sample/sockops.c"
    r3 = IMMEDIATE(64);
    // EBPF_OP_MOV64_IMM pc=222 dst=r4 src=r0 offset=0 imm=0
#line 58 "sample/sockops.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=223 dst=r0 src=r0 offset=0 imm=11
#line 58 "sample/sockops.c"
    r0 = connection_monitor_helpers[1].address
#line 58 "sample/sockops.c"
         (r1, r2, r3, r4, r5);
#line 58 "sample/sockops.c"
    if ((connection_monitor_helpers[1].tail_call) && (r0 == 0))
#line 58 "sample/sockops.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=224 dst=r6 src=r0 offset=0 imm=0
#line 58 "sample/sockops.c"
    r6 = r0;
label_13:
    // EBPF_OP_MOV64_REG pc=225 dst=r0 src=r6 offset=0 imm=0
#line 92 "sample/sockops.c"
    r0 = r6;
    // EBPF_OP_EXIT pc=226 dst=r0 src=r0 offset=0 imm=0
#line 92 "sample/sockops.c"
    return r0;
#line 92 "sample/sockops.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        connection_monitor,
        "sockops",
        "sockops",
        "connection_monitor",
        connection_monitor_maps,
        2,
        connection_monitor_helpers,
        2,
        227,
        &connection_monitor_program_type_guid,
        &connection_monitor_attach_type_guid,
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
    version->minor = 7;
    version->revision = 0;
}

metadata_table_t sockops_metadata_table = {sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version};
