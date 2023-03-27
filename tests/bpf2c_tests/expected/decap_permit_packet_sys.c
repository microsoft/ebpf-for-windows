// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from decap_permit_packet.o

#define NO_CRT
#include "bpf2c.h"

#include <guiddef.h>
#include <wdm.h>
#include <wsk.h>

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
RTL_QUERY_REGISTRY_ROUTINE static _bpf2c_query_registry_routine;

#define metadata_table decap_permit_packet##_metadata_table

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

static helper_function_entry_t decapsulate_permit_packet_helpers[] = {
    {NULL, 65536, "helper_id_65536"},
};

static GUID decapsulate_permit_packet_program_type_guid = {
    0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID decapsulate_permit_packet_attach_type_guid = {
    0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
#pragma code_seg(push, "xdp/de~1")
static uint64_t
decapsulate_permit_packet(void* context)
#line 88 "sample/decap_permit_packet.c"
{
#line 88 "sample/decap_permit_packet.c"
    // Prologue
#line 88 "sample/decap_permit_packet.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 88 "sample/decap_permit_packet.c"
    register uint64_t r0 = 0;
#line 88 "sample/decap_permit_packet.c"
    register uint64_t r1 = 0;
#line 88 "sample/decap_permit_packet.c"
    register uint64_t r2 = 0;
#line 88 "sample/decap_permit_packet.c"
    register uint64_t r3 = 0;
#line 88 "sample/decap_permit_packet.c"
    register uint64_t r4 = 0;
#line 88 "sample/decap_permit_packet.c"
    register uint64_t r5 = 0;
#line 88 "sample/decap_permit_packet.c"
    register uint64_t r10 = 0;

#line 88 "sample/decap_permit_packet.c"
    r1 = (uintptr_t)context;
#line 88 "sample/decap_permit_packet.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r0 src=r0 offset=0 imm=1
#line 88 "sample/decap_permit_packet.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_LDXDW pc=1 dst=r3 src=r1 offset=8 imm=0
#line 94 "sample/decap_permit_packet.c"
    r3 = *(uint64_t*)(uintptr_t)(r1 + OFFSET(8));
    // EBPF_OP_LDXDW pc=2 dst=r2 src=r1 offset=0 imm=0
#line 93 "sample/decap_permit_packet.c"
    r2 = *(uint64_t*)(uintptr_t)(r1 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=3 dst=r4 src=r2 offset=0 imm=0
#line 94 "sample/decap_permit_packet.c"
    r4 = r2;
    // EBPF_OP_ADD64_IMM pc=4 dst=r4 src=r0 offset=0 imm=14
#line 94 "sample/decap_permit_packet.c"
    r4 += IMMEDIATE(14);
    // EBPF_OP_JGT_REG pc=5 dst=r4 src=r3 offset=103 imm=0
#line 94 "sample/decap_permit_packet.c"
    if (r4 > r3)
#line 94 "sample/decap_permit_packet.c"
        goto label_3;
        // EBPF_OP_LDXH pc=6 dst=r5 src=r2 offset=12 imm=0
#line 99 "sample/decap_permit_packet.c"
    r5 = *(uint16_t*)(uintptr_t)(r2 + OFFSET(12));
    // EBPF_OP_JEQ_IMM pc=7 dst=r5 src=r0 offset=56 imm=56710
#line 99 "sample/decap_permit_packet.c"
    if (r5 == IMMEDIATE(56710))
#line 99 "sample/decap_permit_packet.c"
        goto label_1;
        // EBPF_OP_JNE_IMM pc=8 dst=r5 src=r0 offset=100 imm=8
#line 99 "sample/decap_permit_packet.c"
    if (r5 != IMMEDIATE(8))
#line 99 "sample/decap_permit_packet.c"
        goto label_3;
        // EBPF_OP_MOV64_REG pc=9 dst=r5 src=r2 offset=0 imm=0
#line 100 "sample/decap_permit_packet.c"
    r5 = r2;
    // EBPF_OP_ADD64_IMM pc=10 dst=r5 src=r0 offset=0 imm=34
#line 100 "sample/decap_permit_packet.c"
    r5 += IMMEDIATE(34);
    // EBPF_OP_JGT_REG pc=11 dst=r5 src=r3 offset=97 imm=0
#line 100 "sample/decap_permit_packet.c"
    if (r5 > r3)
#line 100 "sample/decap_permit_packet.c"
        goto label_3;
        // EBPF_OP_LDXB pc=12 dst=r5 src=r2 offset=23 imm=0
#line 106 "sample/decap_permit_packet.c"
    r5 = *(uint8_t*)(uintptr_t)(r2 + OFFSET(23));
    // EBPF_OP_JNE_IMM pc=13 dst=r5 src=r0 offset=95 imm=4
#line 106 "sample/decap_permit_packet.c"
    if (r5 != IMMEDIATE(4))
#line 106 "sample/decap_permit_packet.c"
        goto label_3;
        // EBPF_OP_LDXB pc=14 dst=r5 src=r4 offset=0 imm=0
#line 105 "sample/decap_permit_packet.c"
    r5 = *(uint8_t*)(uintptr_t)(r4 + OFFSET(0));
    // EBPF_OP_LSH64_IMM pc=15 dst=r5 src=r0 offset=0 imm=2
#line 105 "sample/decap_permit_packet.c"
    r5 <<= IMMEDIATE(2);
    // EBPF_OP_AND64_IMM pc=16 dst=r5 src=r0 offset=0 imm=60
#line 105 "sample/decap_permit_packet.c"
    r5 &= IMMEDIATE(60);
    // EBPF_OP_ADD64_REG pc=17 dst=r4 src=r5 offset=0 imm=0
#line 105 "sample/decap_permit_packet.c"
    r4 += r5;
    // EBPF_OP_ADD64_IMM pc=18 dst=r4 src=r0 offset=0 imm=20
#line 107 "sample/decap_permit_packet.c"
    r4 += IMMEDIATE(20);
    // EBPF_OP_JGT_REG pc=19 dst=r4 src=r3 offset=89 imm=0
#line 107 "sample/decap_permit_packet.c"
    if (r4 > r3)
#line 107 "sample/decap_permit_packet.c"
        goto label_3;
        // EBPF_OP_MOV64_REG pc=20 dst=r4 src=r2 offset=0 imm=0
#line 29 "sample/decap_permit_packet.c"
    r4 = r2;
    // EBPF_OP_ADD64_REG pc=21 dst=r4 src=r5 offset=0 imm=0
#line 29 "sample/decap_permit_packet.c"
    r4 += r5;
    // EBPF_OP_MOV64_IMM pc=22 dst=r0 src=r0 offset=0 imm=2
#line 29 "sample/decap_permit_packet.c"
    r0 = IMMEDIATE(2);
    // EBPF_OP_JGT_REG pc=23 dst=r4 src=r3 offset=85 imm=0
#line 29 "sample/decap_permit_packet.c"
    if (r4 > r3)
#line 29 "sample/decap_permit_packet.c"
        goto label_3;
        // EBPF_OP_MOV64_REG pc=24 dst=r5 src=r4 offset=0 imm=0
#line 29 "sample/decap_permit_packet.c"
    r5 = r4;
    // EBPF_OP_ADD64_IMM pc=25 dst=r5 src=r0 offset=0 imm=14
#line 29 "sample/decap_permit_packet.c"
    r5 += IMMEDIATE(14);
    // EBPF_OP_JGT_REG pc=26 dst=r5 src=r3 offset=82 imm=0
#line 29 "sample/decap_permit_packet.c"
    if (r5 > r3)
#line 29 "sample/decap_permit_packet.c"
        goto label_3;
        // EBPF_OP_LDXB pc=27 dst=r3 src=r2 offset=13 imm=0
#line 38 "sample/decap_permit_packet.c"
    r3 = *(uint8_t*)(uintptr_t)(r2 + OFFSET(13));
    // EBPF_OP_STXB pc=28 dst=r4 src=r3 offset=13 imm=0
#line 38 "sample/decap_permit_packet.c"
    *(uint8_t*)(uintptr_t)(r4 + OFFSET(13)) = (uint8_t)r3;
    // EBPF_OP_LDXB pc=29 dst=r3 src=r2 offset=12 imm=0
#line 38 "sample/decap_permit_packet.c"
    r3 = *(uint8_t*)(uintptr_t)(r2 + OFFSET(12));
    // EBPF_OP_STXB pc=30 dst=r4 src=r3 offset=12 imm=0
#line 38 "sample/decap_permit_packet.c"
    *(uint8_t*)(uintptr_t)(r4 + OFFSET(12)) = (uint8_t)r3;
    // EBPF_OP_LDXB pc=31 dst=r3 src=r2 offset=11 imm=0
#line 38 "sample/decap_permit_packet.c"
    r3 = *(uint8_t*)(uintptr_t)(r2 + OFFSET(11));
    // EBPF_OP_STXB pc=32 dst=r4 src=r3 offset=11 imm=0
#line 38 "sample/decap_permit_packet.c"
    *(uint8_t*)(uintptr_t)(r4 + OFFSET(11)) = (uint8_t)r3;
    // EBPF_OP_LDXB pc=33 dst=r3 src=r2 offset=10 imm=0
#line 38 "sample/decap_permit_packet.c"
    r3 = *(uint8_t*)(uintptr_t)(r2 + OFFSET(10));
    // EBPF_OP_STXB pc=34 dst=r4 src=r3 offset=10 imm=0
#line 38 "sample/decap_permit_packet.c"
    *(uint8_t*)(uintptr_t)(r4 + OFFSET(10)) = (uint8_t)r3;
    // EBPF_OP_LDXB pc=35 dst=r3 src=r2 offset=9 imm=0
#line 38 "sample/decap_permit_packet.c"
    r3 = *(uint8_t*)(uintptr_t)(r2 + OFFSET(9));
    // EBPF_OP_STXB pc=36 dst=r4 src=r3 offset=9 imm=0
#line 38 "sample/decap_permit_packet.c"
    *(uint8_t*)(uintptr_t)(r4 + OFFSET(9)) = (uint8_t)r3;
    // EBPF_OP_LDXB pc=37 dst=r3 src=r2 offset=8 imm=0
#line 38 "sample/decap_permit_packet.c"
    r3 = *(uint8_t*)(uintptr_t)(r2 + OFFSET(8));
    // EBPF_OP_STXB pc=38 dst=r4 src=r3 offset=8 imm=0
#line 38 "sample/decap_permit_packet.c"
    *(uint8_t*)(uintptr_t)(r4 + OFFSET(8)) = (uint8_t)r3;
    // EBPF_OP_LDXB pc=39 dst=r3 src=r2 offset=7 imm=0
#line 38 "sample/decap_permit_packet.c"
    r3 = *(uint8_t*)(uintptr_t)(r2 + OFFSET(7));
    // EBPF_OP_STXB pc=40 dst=r4 src=r3 offset=7 imm=0
#line 38 "sample/decap_permit_packet.c"
    *(uint8_t*)(uintptr_t)(r4 + OFFSET(7)) = (uint8_t)r3;
    // EBPF_OP_LDXB pc=41 dst=r3 src=r2 offset=6 imm=0
#line 38 "sample/decap_permit_packet.c"
    r3 = *(uint8_t*)(uintptr_t)(r2 + OFFSET(6));
    // EBPF_OP_STXB pc=42 dst=r4 src=r3 offset=6 imm=0
#line 38 "sample/decap_permit_packet.c"
    *(uint8_t*)(uintptr_t)(r4 + OFFSET(6)) = (uint8_t)r3;
    // EBPF_OP_LDXB pc=43 dst=r3 src=r2 offset=5 imm=0
#line 38 "sample/decap_permit_packet.c"
    r3 = *(uint8_t*)(uintptr_t)(r2 + OFFSET(5));
    // EBPF_OP_STXB pc=44 dst=r4 src=r3 offset=5 imm=0
#line 38 "sample/decap_permit_packet.c"
    *(uint8_t*)(uintptr_t)(r4 + OFFSET(5)) = (uint8_t)r3;
    // EBPF_OP_LDXB pc=45 dst=r3 src=r2 offset=4 imm=0
#line 38 "sample/decap_permit_packet.c"
    r3 = *(uint8_t*)(uintptr_t)(r2 + OFFSET(4));
    // EBPF_OP_STXB pc=46 dst=r4 src=r3 offset=4 imm=0
#line 38 "sample/decap_permit_packet.c"
    *(uint8_t*)(uintptr_t)(r4 + OFFSET(4)) = (uint8_t)r3;
    // EBPF_OP_LDXB pc=47 dst=r3 src=r2 offset=3 imm=0
#line 38 "sample/decap_permit_packet.c"
    r3 = *(uint8_t*)(uintptr_t)(r2 + OFFSET(3));
    // EBPF_OP_STXB pc=48 dst=r4 src=r3 offset=3 imm=0
#line 38 "sample/decap_permit_packet.c"
    *(uint8_t*)(uintptr_t)(r4 + OFFSET(3)) = (uint8_t)r3;
    // EBPF_OP_LDXB pc=49 dst=r3 src=r2 offset=2 imm=0
#line 38 "sample/decap_permit_packet.c"
    r3 = *(uint8_t*)(uintptr_t)(r2 + OFFSET(2));
    // EBPF_OP_STXB pc=50 dst=r4 src=r3 offset=2 imm=0
#line 38 "sample/decap_permit_packet.c"
    *(uint8_t*)(uintptr_t)(r4 + OFFSET(2)) = (uint8_t)r3;
    // EBPF_OP_LDXB pc=51 dst=r3 src=r2 offset=1 imm=0
#line 38 "sample/decap_permit_packet.c"
    r3 = *(uint8_t*)(uintptr_t)(r2 + OFFSET(1));
    // EBPF_OP_STXB pc=52 dst=r4 src=r3 offset=1 imm=0
#line 38 "sample/decap_permit_packet.c"
    *(uint8_t*)(uintptr_t)(r4 + OFFSET(1)) = (uint8_t)r3;
    // EBPF_OP_LDXB pc=53 dst=r2 src=r2 offset=0 imm=0
#line 38 "sample/decap_permit_packet.c"
    r2 = *(uint8_t*)(uintptr_t)(r2 + OFFSET(0));
    // EBPF_OP_STXB pc=54 dst=r4 src=r2 offset=0 imm=0
#line 38 "sample/decap_permit_packet.c"
    *(uint8_t*)(uintptr_t)(r4 + OFFSET(0)) = (uint8_t)r2;
    // EBPF_OP_MOV64_IMM pc=55 dst=r2 src=r0 offset=0 imm=20
#line 41 "sample/decap_permit_packet.c"
    r2 = IMMEDIATE(20);
    // EBPF_OP_CALL pc=56 dst=r0 src=r0 offset=0 imm=65536
#line 41 "sample/decap_permit_packet.c"
    r0 = decapsulate_permit_packet_helpers[0].address
#line 41 "sample/decap_permit_packet.c"
         (r1, r2, r3, r4, r5);
#line 41 "sample/decap_permit_packet.c"
    if ((decapsulate_permit_packet_helpers[0].tail_call) && (r0 == 0))
#line 41 "sample/decap_permit_packet.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=57 dst=r1 src=r0 offset=0 imm=0
#line 41 "sample/decap_permit_packet.c"
    r1 = r0;
    // EBPF_OP_LSH64_IMM pc=58 dst=r1 src=r0 offset=0 imm=32
#line 41 "sample/decap_permit_packet.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=59 dst=r1 src=r0 offset=0 imm=32
#line 41 "sample/decap_permit_packet.c"
    r1 = (int64_t)r1 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_IMM pc=60 dst=r0 src=r0 offset=0 imm=2
#line 41 "sample/decap_permit_packet.c"
    r0 = IMMEDIATE(2);
    // EBPF_OP_MOV64_IMM pc=61 dst=r2 src=r0 offset=0 imm=0
#line 41 "sample/decap_permit_packet.c"
    r2 = IMMEDIATE(0);
    // EBPF_OP_JSGT_REG pc=62 dst=r2 src=r1 offset=46 imm=0
#line 41 "sample/decap_permit_packet.c"
    if ((int64_t)r2 > (int64_t)r1)
#line 41 "sample/decap_permit_packet.c"
        goto label_3;
        // EBPF_OP_JA pc=63 dst=r0 src=r0 offset=44 imm=0
#line 41 "sample/decap_permit_packet.c"
    goto label_2;
label_1:
    // EBPF_OP_MOV64_REG pc=64 dst=r4 src=r2 offset=0 imm=0
#line 114 "sample/decap_permit_packet.c"
    r4 = r2;
    // EBPF_OP_ADD64_IMM pc=65 dst=r4 src=r0 offset=0 imm=54
#line 114 "sample/decap_permit_packet.c"
    r4 += IMMEDIATE(54);
    // EBPF_OP_JGT_REG pc=66 dst=r4 src=r3 offset=42 imm=0
#line 114 "sample/decap_permit_packet.c"
    if (r4 > r3)
#line 114 "sample/decap_permit_packet.c"
        goto label_3;
        // EBPF_OP_MOV64_REG pc=67 dst=r4 src=r2 offset=0 imm=0
#line 114 "sample/decap_permit_packet.c"
    r4 = r2;
    // EBPF_OP_ADD64_IMM pc=68 dst=r4 src=r0 offset=0 imm=94
#line 114 "sample/decap_permit_packet.c"
    r4 += IMMEDIATE(94);
    // EBPF_OP_JGT_REG pc=69 dst=r4 src=r3 offset=39 imm=0
#line 120 "sample/decap_permit_packet.c"
    if (r4 > r3)
#line 120 "sample/decap_permit_packet.c"
        goto label_3;
        // EBPF_OP_LDXB pc=70 dst=r3 src=r2 offset=20 imm=0
#line 120 "sample/decap_permit_packet.c"
    r3 = *(uint8_t*)(uintptr_t)(r2 + OFFSET(20));
    // EBPF_OP_JNE_IMM pc=71 dst=r3 src=r0 offset=37 imm=41
#line 120 "sample/decap_permit_packet.c"
    if (r3 != IMMEDIATE(41))
#line 120 "sample/decap_permit_packet.c"
        goto label_3;
        // EBPF_OP_LDXB pc=72 dst=r3 src=r2 offset=13 imm=0
#line 67 "sample/decap_permit_packet.c"
    r3 = *(uint8_t*)(uintptr_t)(r2 + OFFSET(13));
    // EBPF_OP_STXB pc=73 dst=r2 src=r3 offset=53 imm=0
#line 67 "sample/decap_permit_packet.c"
    *(uint8_t*)(uintptr_t)(r2 + OFFSET(53)) = (uint8_t)r3;
    // EBPF_OP_LDXB pc=74 dst=r3 src=r2 offset=12 imm=0
#line 67 "sample/decap_permit_packet.c"
    r3 = *(uint8_t*)(uintptr_t)(r2 + OFFSET(12));
    // EBPF_OP_STXB pc=75 dst=r2 src=r3 offset=52 imm=0
#line 67 "sample/decap_permit_packet.c"
    *(uint8_t*)(uintptr_t)(r2 + OFFSET(52)) = (uint8_t)r3;
    // EBPF_OP_LDXB pc=76 dst=r3 src=r2 offset=11 imm=0
#line 67 "sample/decap_permit_packet.c"
    r3 = *(uint8_t*)(uintptr_t)(r2 + OFFSET(11));
    // EBPF_OP_STXB pc=77 dst=r2 src=r3 offset=51 imm=0
#line 67 "sample/decap_permit_packet.c"
    *(uint8_t*)(uintptr_t)(r2 + OFFSET(51)) = (uint8_t)r3;
    // EBPF_OP_LDXB pc=78 dst=r3 src=r2 offset=10 imm=0
#line 67 "sample/decap_permit_packet.c"
    r3 = *(uint8_t*)(uintptr_t)(r2 + OFFSET(10));
    // EBPF_OP_STXB pc=79 dst=r2 src=r3 offset=50 imm=0
#line 67 "sample/decap_permit_packet.c"
    *(uint8_t*)(uintptr_t)(r2 + OFFSET(50)) = (uint8_t)r3;
    // EBPF_OP_LDXB pc=80 dst=r3 src=r2 offset=9 imm=0
#line 67 "sample/decap_permit_packet.c"
    r3 = *(uint8_t*)(uintptr_t)(r2 + OFFSET(9));
    // EBPF_OP_STXB pc=81 dst=r2 src=r3 offset=49 imm=0
#line 67 "sample/decap_permit_packet.c"
    *(uint8_t*)(uintptr_t)(r2 + OFFSET(49)) = (uint8_t)r3;
    // EBPF_OP_LDXB pc=82 dst=r3 src=r2 offset=8 imm=0
#line 67 "sample/decap_permit_packet.c"
    r3 = *(uint8_t*)(uintptr_t)(r2 + OFFSET(8));
    // EBPF_OP_STXB pc=83 dst=r2 src=r3 offset=48 imm=0
#line 67 "sample/decap_permit_packet.c"
    *(uint8_t*)(uintptr_t)(r2 + OFFSET(48)) = (uint8_t)r3;
    // EBPF_OP_LDXB pc=84 dst=r3 src=r2 offset=7 imm=0
#line 67 "sample/decap_permit_packet.c"
    r3 = *(uint8_t*)(uintptr_t)(r2 + OFFSET(7));
    // EBPF_OP_STXB pc=85 dst=r2 src=r3 offset=47 imm=0
#line 67 "sample/decap_permit_packet.c"
    *(uint8_t*)(uintptr_t)(r2 + OFFSET(47)) = (uint8_t)r3;
    // EBPF_OP_LDXB pc=86 dst=r3 src=r2 offset=6 imm=0
#line 67 "sample/decap_permit_packet.c"
    r3 = *(uint8_t*)(uintptr_t)(r2 + OFFSET(6));
    // EBPF_OP_STXB pc=87 dst=r2 src=r3 offset=46 imm=0
#line 67 "sample/decap_permit_packet.c"
    *(uint8_t*)(uintptr_t)(r2 + OFFSET(46)) = (uint8_t)r3;
    // EBPF_OP_LDXB pc=88 dst=r3 src=r2 offset=5 imm=0
#line 67 "sample/decap_permit_packet.c"
    r3 = *(uint8_t*)(uintptr_t)(r2 + OFFSET(5));
    // EBPF_OP_STXB pc=89 dst=r2 src=r3 offset=45 imm=0
#line 67 "sample/decap_permit_packet.c"
    *(uint8_t*)(uintptr_t)(r2 + OFFSET(45)) = (uint8_t)r3;
    // EBPF_OP_LDXB pc=90 dst=r3 src=r2 offset=4 imm=0
#line 67 "sample/decap_permit_packet.c"
    r3 = *(uint8_t*)(uintptr_t)(r2 + OFFSET(4));
    // EBPF_OP_STXB pc=91 dst=r2 src=r3 offset=44 imm=0
#line 67 "sample/decap_permit_packet.c"
    *(uint8_t*)(uintptr_t)(r2 + OFFSET(44)) = (uint8_t)r3;
    // EBPF_OP_LDXB pc=92 dst=r3 src=r2 offset=3 imm=0
#line 67 "sample/decap_permit_packet.c"
    r3 = *(uint8_t*)(uintptr_t)(r2 + OFFSET(3));
    // EBPF_OP_STXB pc=93 dst=r2 src=r3 offset=43 imm=0
#line 67 "sample/decap_permit_packet.c"
    *(uint8_t*)(uintptr_t)(r2 + OFFSET(43)) = (uint8_t)r3;
    // EBPF_OP_LDXB pc=94 dst=r3 src=r2 offset=2 imm=0
#line 67 "sample/decap_permit_packet.c"
    r3 = *(uint8_t*)(uintptr_t)(r2 + OFFSET(2));
    // EBPF_OP_STXB pc=95 dst=r2 src=r3 offset=42 imm=0
#line 67 "sample/decap_permit_packet.c"
    *(uint8_t*)(uintptr_t)(r2 + OFFSET(42)) = (uint8_t)r3;
    // EBPF_OP_LDXB pc=96 dst=r3 src=r2 offset=1 imm=0
#line 67 "sample/decap_permit_packet.c"
    r3 = *(uint8_t*)(uintptr_t)(r2 + OFFSET(1));
    // EBPF_OP_STXB pc=97 dst=r2 src=r3 offset=41 imm=0
#line 67 "sample/decap_permit_packet.c"
    *(uint8_t*)(uintptr_t)(r2 + OFFSET(41)) = (uint8_t)r3;
    // EBPF_OP_LDXB pc=98 dst=r3 src=r2 offset=0 imm=0
#line 67 "sample/decap_permit_packet.c"
    r3 = *(uint8_t*)(uintptr_t)(r2 + OFFSET(0));
    // EBPF_OP_STXB pc=99 dst=r2 src=r3 offset=40 imm=0
#line 67 "sample/decap_permit_packet.c"
    *(uint8_t*)(uintptr_t)(r2 + OFFSET(40)) = (uint8_t)r3;
    // EBPF_OP_MOV64_IMM pc=100 dst=r2 src=r0 offset=0 imm=40
#line 70 "sample/decap_permit_packet.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_CALL pc=101 dst=r0 src=r0 offset=0 imm=65536
#line 70 "sample/decap_permit_packet.c"
    r0 = decapsulate_permit_packet_helpers[0].address
#line 70 "sample/decap_permit_packet.c"
         (r1, r2, r3, r4, r5);
#line 70 "sample/decap_permit_packet.c"
    if ((decapsulate_permit_packet_helpers[0].tail_call) && (r0 == 0))
#line 70 "sample/decap_permit_packet.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=102 dst=r1 src=r0 offset=0 imm=0
#line 70 "sample/decap_permit_packet.c"
    r1 = r0;
    // EBPF_OP_LSH64_IMM pc=103 dst=r1 src=r0 offset=0 imm=32
#line 70 "sample/decap_permit_packet.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=104 dst=r1 src=r0 offset=0 imm=32
#line 70 "sample/decap_permit_packet.c"
    r1 = (int64_t)r1 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_IMM pc=105 dst=r0 src=r0 offset=0 imm=2
#line 70 "sample/decap_permit_packet.c"
    r0 = IMMEDIATE(2);
    // EBPF_OP_MOV64_IMM pc=106 dst=r2 src=r0 offset=0 imm=0
#line 70 "sample/decap_permit_packet.c"
    r2 = IMMEDIATE(0);
    // EBPF_OP_JSGT_REG pc=107 dst=r2 src=r1 offset=1 imm=0
#line 70 "sample/decap_permit_packet.c"
    if ((int64_t)r2 > (int64_t)r1)
#line 70 "sample/decap_permit_packet.c"
        goto label_3;
label_2:
    // EBPF_OP_MOV64_IMM pc=108 dst=r0 src=r0 offset=0 imm=1
#line 70 "sample/decap_permit_packet.c"
    r0 = IMMEDIATE(1);
label_3:
    // EBPF_OP_EXIT pc=109 dst=r0 src=r0 offset=0 imm=0
#line 131 "sample/decap_permit_packet.c"
    return r0;
#line 131 "sample/decap_permit_packet.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        decapsulate_permit_packet,
        "xdp/de~1",
        "xdp/decapsulate_reflect",
        "decapsulate_permit_packet",
        NULL,
        0,
        decapsulate_permit_packet_helpers,
        1,
        110,
        &decapsulate_permit_packet_program_type_guid,
        &decapsulate_permit_packet_attach_type_guid,
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

metadata_table_t decap_permit_packet_metadata_table = {
    sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version};
