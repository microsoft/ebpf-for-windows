// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from encap_reflect_packet.o

#define NO_CRT
#include "bpf2c.h"

#include <guiddef.h>
#include <wdm.h>
#include <wsk.h>

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
RTL_QUERY_REGISTRY_ROUTINE static _bpf2c_query_registry_routine;

#define metadata_table encap_reflect_packet##_metadata_table

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

static helper_function_entry_t encap_reflect_packet_helpers[] = {
    {NULL, 65536, "helper_id_65536"},
    {NULL, 10, "helper_id_10"},
};

static GUID encap_reflect_packet_program_type_guid = {
    0xce8ccef8, 0x4241, 0x4975, {0x98, 0x4d, 0xbb, 0x39, 0x21, 0xdf, 0xa7, 0x3c}};
static GUID encap_reflect_packet_attach_type_guid = {
    0x0dccc15d, 0xa5f9, 0x4dc1, {0xac, 0x79, 0xfa, 0x25, 0xee, 0xf2, 0x15, 0xc3}};
#pragma code_seg(push, "xdp_te~1")
static uint64_t
encap_reflect_packet(void* context)
#line 167 "sample/encap_reflect_packet.c"
{
#line 167 "sample/encap_reflect_packet.c"
    // Prologue
#line 167 "sample/encap_reflect_packet.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 167 "sample/encap_reflect_packet.c"
    register uint64_t r0 = 0;
#line 167 "sample/encap_reflect_packet.c"
    register uint64_t r1 = 0;
#line 167 "sample/encap_reflect_packet.c"
    register uint64_t r2 = 0;
#line 167 "sample/encap_reflect_packet.c"
    register uint64_t r3 = 0;
#line 167 "sample/encap_reflect_packet.c"
    register uint64_t r4 = 0;
#line 167 "sample/encap_reflect_packet.c"
    register uint64_t r5 = 0;
#line 167 "sample/encap_reflect_packet.c"
    register uint64_t r6 = 0;
#line 167 "sample/encap_reflect_packet.c"
    register uint64_t r7 = 0;
#line 167 "sample/encap_reflect_packet.c"
    register uint64_t r8 = 0;
#line 167 "sample/encap_reflect_packet.c"
    register uint64_t r10 = 0;

#line 167 "sample/encap_reflect_packet.c"
    r1 = (uintptr_t)context;
#line 167 "sample/encap_reflect_packet.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 167 "sample/encap_reflect_packet.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r0 src=r0 offset=0 imm=1
#line 167 "sample/encap_reflect_packet.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_LDXDW pc=2 dst=r1 src=r6 offset=8 imm=0
#line 173 "sample/encap_reflect_packet.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_LDXDW pc=3 dst=r2 src=r6 offset=0 imm=0
#line 172 "sample/encap_reflect_packet.c"
    r2 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=4 dst=r3 src=r2 offset=0 imm=0
#line 173 "sample/encap_reflect_packet.c"
    r3 = r2;
    // EBPF_OP_ADD64_IMM pc=5 dst=r3 src=r0 offset=0 imm=14
#line 173 "sample/encap_reflect_packet.c"
    r3 += IMMEDIATE(14);
    // EBPF_OP_JGT_REG pc=6 dst=r3 src=r1 offset=315 imm=0
#line 173 "sample/encap_reflect_packet.c"
    if (r3 > r1)
#line 173 "sample/encap_reflect_packet.c"
        goto label_5;
        // EBPF_OP_LDXH pc=7 dst=r4 src=r2 offset=12 imm=0
#line 178 "sample/encap_reflect_packet.c"
    r4 = *(uint16_t*)(uintptr_t)(r2 + OFFSET(12));
    // EBPF_OP_JEQ_IMM pc=8 dst=r4 src=r0 offset=120 imm=56710
#line 178 "sample/encap_reflect_packet.c"
    if (r4 == IMMEDIATE(56710))
#line 178 "sample/encap_reflect_packet.c"
        goto label_2;
        // EBPF_OP_JNE_IMM pc=9 dst=r4 src=r0 offset=312 imm=8
#line 178 "sample/encap_reflect_packet.c"
    if (r4 != IMMEDIATE(8))
#line 178 "sample/encap_reflect_packet.c"
        goto label_5;
        // EBPF_OP_MOV64_REG pc=10 dst=r4 src=r2 offset=0 imm=0
#line 179 "sample/encap_reflect_packet.c"
    r4 = r2;
    // EBPF_OP_ADD64_IMM pc=11 dst=r4 src=r0 offset=0 imm=34
#line 179 "sample/encap_reflect_packet.c"
    r4 += IMMEDIATE(34);
    // EBPF_OP_JGT_REG pc=12 dst=r4 src=r1 offset=309 imm=0
#line 179 "sample/encap_reflect_packet.c"
    if (r4 > r1)
#line 179 "sample/encap_reflect_packet.c"
        goto label_5;
        // EBPF_OP_LDXB pc=13 dst=r4 src=r2 offset=23 imm=0
#line 185 "sample/encap_reflect_packet.c"
    r4 = *(uint8_t*)(uintptr_t)(r2 + OFFSET(23));
    // EBPF_OP_JNE_IMM pc=14 dst=r4 src=r0 offset=307 imm=17
#line 185 "sample/encap_reflect_packet.c"
    if (r4 != IMMEDIATE(17))
#line 185 "sample/encap_reflect_packet.c"
        goto label_5;
        // EBPF_OP_LDXB pc=15 dst=r2 src=r2 offset=14 imm=0
#line 185 "sample/encap_reflect_packet.c"
    r2 = *(uint8_t*)(uintptr_t)(r2 + OFFSET(14));
    // EBPF_OP_LSH64_IMM pc=16 dst=r2 src=r0 offset=0 imm=2
#line 185 "sample/encap_reflect_packet.c"
    r2 <<= (IMMEDIATE(2) & 63);
    // EBPF_OP_AND64_IMM pc=17 dst=r2 src=r0 offset=0 imm=60
#line 185 "sample/encap_reflect_packet.c"
    r2 &= IMMEDIATE(60);
    // EBPF_OP_ADD64_REG pc=18 dst=r3 src=r2 offset=0 imm=0
#line 185 "sample/encap_reflect_packet.c"
    r3 += r2;
    // EBPF_OP_MOV64_REG pc=19 dst=r2 src=r3 offset=0 imm=0
#line 185 "sample/encap_reflect_packet.c"
    r2 = r3;
    // EBPF_OP_ADD64_IMM pc=20 dst=r2 src=r0 offset=0 imm=8
#line 185 "sample/encap_reflect_packet.c"
    r2 += IMMEDIATE(8);
    // EBPF_OP_JGT_REG pc=21 dst=r2 src=r1 offset=300 imm=0
#line 185 "sample/encap_reflect_packet.c"
    if (r2 > r1)
#line 185 "sample/encap_reflect_packet.c"
        goto label_5;
        // EBPF_OP_LDXH pc=22 dst=r1 src=r3 offset=2 imm=0
#line 191 "sample/encap_reflect_packet.c"
    r1 = *(uint16_t*)(uintptr_t)(r3 + OFFSET(2));
    // EBPF_OP_JNE_IMM pc=23 dst=r1 src=r0 offset=298 imm=7459
#line 191 "sample/encap_reflect_packet.c"
    if (r1 != IMMEDIATE(7459))
#line 191 "sample/encap_reflect_packet.c"
        goto label_5;
        // EBPF_OP_MOV64_REG pc=24 dst=r1 src=r6 offset=0 imm=0
#line 22 "sample/encap_reflect_packet.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=25 dst=r2 src=r0 offset=0 imm=-20
#line 22 "sample/encap_reflect_packet.c"
    r2 = (uint64_t)4294967276;
    // EBPF_OP_CALL pc=27 dst=r0 src=r0 offset=0 imm=65536
#line 22 "sample/encap_reflect_packet.c"
    r0 = encap_reflect_packet_helpers[0].address
#line 22 "sample/encap_reflect_packet.c"
         (r1, r2, r3, r4, r5);
#line 22 "sample/encap_reflect_packet.c"
    if ((encap_reflect_packet_helpers[0].tail_call) && (r0 == 0))
#line 22 "sample/encap_reflect_packet.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=28 dst=r1 src=r0 offset=0 imm=0
#line 22 "sample/encap_reflect_packet.c"
    r1 = r0;
    // EBPF_OP_MOV64_IMM pc=29 dst=r0 src=r0 offset=0 imm=2
#line 22 "sample/encap_reflect_packet.c"
    r0 = IMMEDIATE(2);
    // EBPF_OP_LSH64_IMM pc=30 dst=r1 src=r0 offset=0 imm=32
#line 22 "sample/encap_reflect_packet.c"
    r1 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=31 dst=r1 src=r0 offset=0 imm=32
#line 22 "sample/encap_reflect_packet.c"
    r1 = (int64_t)r1 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_IMM pc=32 dst=r2 src=r0 offset=0 imm=0
#line 22 "sample/encap_reflect_packet.c"
    r2 = IMMEDIATE(0);
    // EBPF_OP_JSGT_REG pc=33 dst=r2 src=r1 offset=288 imm=0
#line 22 "sample/encap_reflect_packet.c"
    if ((int64_t)r2 > (int64_t)r1)
#line 22 "sample/encap_reflect_packet.c"
        goto label_5;
        // EBPF_OP_LDXDW pc=34 dst=r4 src=r6 offset=8 imm=0
#line 28 "sample/encap_reflect_packet.c"
    r4 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_LDXDW pc=35 dst=r7 src=r6 offset=0 imm=0
#line 27 "sample/encap_reflect_packet.c"
    r7 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=36 dst=r3 src=r7 offset=0 imm=0
#line 28 "sample/encap_reflect_packet.c"
    r3 = r7;
    // EBPF_OP_ADD64_IMM pc=37 dst=r3 src=r0 offset=0 imm=14
#line 28 "sample/encap_reflect_packet.c"
    r3 += IMMEDIATE(14);
    // EBPF_OP_JGT_REG pc=38 dst=r3 src=r4 offset=283 imm=0
#line 28 "sample/encap_reflect_packet.c"
    if (r3 > r4)
#line 28 "sample/encap_reflect_packet.c"
        goto label_5;
        // EBPF_OP_MOV64_REG pc=39 dst=r2 src=r7 offset=0 imm=0
#line 35 "sample/encap_reflect_packet.c"
    r2 = r7;
    // EBPF_OP_ADD64_IMM pc=40 dst=r2 src=r0 offset=0 imm=20
#line 35 "sample/encap_reflect_packet.c"
    r2 += IMMEDIATE(20);
    // EBPF_OP_JGT_REG pc=41 dst=r2 src=r4 offset=280 imm=0
#line 35 "sample/encap_reflect_packet.c"
    if (r2 > r4)
#line 35 "sample/encap_reflect_packet.c"
        goto label_5;
        // EBPF_OP_MOV64_REG pc=42 dst=r1 src=r7 offset=0 imm=0
#line 43 "sample/encap_reflect_packet.c"
    r1 = r7;
    // EBPF_OP_ADD64_IMM pc=43 dst=r1 src=r0 offset=0 imm=34
#line 43 "sample/encap_reflect_packet.c"
    r1 += IMMEDIATE(34);
    // EBPF_OP_JGT_REG pc=44 dst=r1 src=r4 offset=277 imm=0
#line 43 "sample/encap_reflect_packet.c"
    if (r1 > r4)
#line 43 "sample/encap_reflect_packet.c"
        goto label_5;
        // EBPF_OP_MOV64_REG pc=45 dst=r5 src=r7 offset=0 imm=0
#line 43 "sample/encap_reflect_packet.c"
    r5 = r7;
    // EBPF_OP_ADD64_IMM pc=46 dst=r5 src=r0 offset=0 imm=54
#line 43 "sample/encap_reflect_packet.c"
    r5 += IMMEDIATE(54);
    // EBPF_OP_JGT_REG pc=47 dst=r5 src=r4 offset=274 imm=0
#line 43 "sample/encap_reflect_packet.c"
    if (r5 > r4)
#line 43 "sample/encap_reflect_packet.c"
        goto label_5;
        // EBPF_OP_LDXH pc=48 dst=r4 src=r2 offset=4 imm=0
#line 56 "sample/encap_reflect_packet.c"
    r4 = *(uint16_t*)(uintptr_t)(r2 + OFFSET(4));
    // EBPF_OP_STXH pc=49 dst=r7 src=r4 offset=4 imm=0
#line 56 "sample/encap_reflect_packet.c"
    *(uint16_t*)(uintptr_t)(r7 + OFFSET(4)) = (uint16_t)r4;
    // EBPF_OP_LDXH pc=50 dst=r4 src=r2 offset=0 imm=0
#line 56 "sample/encap_reflect_packet.c"
    r4 = *(uint16_t*)(uintptr_t)(r2 + OFFSET(0));
    // EBPF_OP_STXH pc=51 dst=r7 src=r4 offset=0 imm=0
#line 56 "sample/encap_reflect_packet.c"
    *(uint16_t*)(uintptr_t)(r7 + OFFSET(0)) = (uint16_t)r4;
    // EBPF_OP_LDXH pc=52 dst=r4 src=r2 offset=2 imm=0
#line 56 "sample/encap_reflect_packet.c"
    r4 = *(uint16_t*)(uintptr_t)(r2 + OFFSET(2));
    // EBPF_OP_STXH pc=53 dst=r7 src=r4 offset=2 imm=0
#line 56 "sample/encap_reflect_packet.c"
    *(uint16_t*)(uintptr_t)(r7 + OFFSET(2)) = (uint16_t)r4;
    // EBPF_OP_LDXH pc=54 dst=r4 src=r2 offset=12 imm=0
#line 56 "sample/encap_reflect_packet.c"
    r4 = *(uint16_t*)(uintptr_t)(r2 + OFFSET(12));
    // EBPF_OP_STXH pc=55 dst=r7 src=r4 offset=12 imm=0
#line 56 "sample/encap_reflect_packet.c"
    *(uint16_t*)(uintptr_t)(r7 + OFFSET(12)) = (uint16_t)r4;
    // EBPF_OP_LDXH pc=56 dst=r4 src=r2 offset=10 imm=0
#line 56 "sample/encap_reflect_packet.c"
    r4 = *(uint16_t*)(uintptr_t)(r2 + OFFSET(10));
    // EBPF_OP_STXH pc=57 dst=r7 src=r4 offset=10 imm=0
#line 56 "sample/encap_reflect_packet.c"
    *(uint16_t*)(uintptr_t)(r7 + OFFSET(10)) = (uint16_t)r4;
    // EBPF_OP_LDXH pc=58 dst=r5 src=r2 offset=8 imm=0
#line 56 "sample/encap_reflect_packet.c"
    r5 = *(uint16_t*)(uintptr_t)(r2 + OFFSET(8));
    // EBPF_OP_LDXH pc=59 dst=r8 src=r2 offset=6 imm=0
#line 56 "sample/encap_reflect_packet.c"
    r8 = *(uint16_t*)(uintptr_t)(r2 + OFFSET(6));
    // EBPF_OP_STXH pc=60 dst=r7 src=r4 offset=4 imm=0
#line 16 "sample/./xdp_common.h"
    *(uint16_t*)(uintptr_t)(r7 + OFFSET(4)) = (uint16_t)r4;
    // EBPF_OP_STXH pc=61 dst=r7 src=r8 offset=6 imm=0
#line 56 "sample/encap_reflect_packet.c"
    *(uint16_t*)(uintptr_t)(r7 + OFFSET(6)) = (uint16_t)r8;
    // EBPF_OP_STXH pc=62 dst=r7 src=r8 offset=0 imm=0
#line 16 "sample/./xdp_common.h"
    *(uint16_t*)(uintptr_t)(r7 + OFFSET(0)) = (uint16_t)r8;
    // EBPF_OP_STXH pc=63 dst=r7 src=r5 offset=8 imm=0
#line 56 "sample/encap_reflect_packet.c"
    *(uint16_t*)(uintptr_t)(r7 + OFFSET(8)) = (uint16_t)r5;
    // EBPF_OP_STXH pc=64 dst=r7 src=r5 offset=2 imm=0
#line 16 "sample/./xdp_common.h"
    *(uint16_t*)(uintptr_t)(r7 + OFFSET(2)) = (uint16_t)r5;
    // EBPF_OP_LDXH pc=65 dst=r4 src=r2 offset=4 imm=0
#line 17 "sample/./xdp_common.h"
    r4 = *(uint16_t*)(uintptr_t)(r2 + OFFSET(4));
    // EBPF_OP_STXH pc=66 dst=r7 src=r4 offset=10 imm=0
#line 17 "sample/./xdp_common.h"
    *(uint16_t*)(uintptr_t)(r7 + OFFSET(10)) = (uint16_t)r4;
    // EBPF_OP_LDXH pc=67 dst=r4 src=r2 offset=0 imm=0
#line 17 "sample/./xdp_common.h"
    r4 = *(uint16_t*)(uintptr_t)(r2 + OFFSET(0));
    // EBPF_OP_STXH pc=68 dst=r7 src=r4 offset=6 imm=0
#line 17 "sample/./xdp_common.h"
    *(uint16_t*)(uintptr_t)(r7 + OFFSET(6)) = (uint16_t)r4;
    // EBPF_OP_LDXH pc=69 dst=r2 src=r2 offset=2 imm=0
#line 17 "sample/./xdp_common.h"
    r2 = *(uint16_t*)(uintptr_t)(r2 + OFFSET(2));
    // EBPF_OP_STXH pc=70 dst=r7 src=r2 offset=8 imm=0
#line 17 "sample/./xdp_common.h"
    *(uint16_t*)(uintptr_t)(r7 + OFFSET(8)) = (uint16_t)r2;
    // EBPF_OP_LDXW pc=71 dst=r2 src=r7 offset=50 imm=0
#line 23 "sample/./xdp_common.h"
    r2 = *(uint32_t*)(uintptr_t)(r7 + OFFSET(50));
    // EBPF_OP_LDXW pc=72 dst=r4 src=r7 offset=46 imm=0
#line 24 "sample/./xdp_common.h"
    r4 = *(uint32_t*)(uintptr_t)(r7 + OFFSET(46));
    // EBPF_OP_STXW pc=73 dst=r7 src=r4 offset=50 imm=0
#line 24 "sample/./xdp_common.h"
    *(uint32_t*)(uintptr_t)(r7 + OFFSET(50)) = (uint32_t)r4;
    // EBPF_OP_STXW pc=74 dst=r7 src=r2 offset=46 imm=0
#line 25 "sample/./xdp_common.h"
    *(uint32_t*)(uintptr_t)(r7 + OFFSET(46)) = (uint32_t)r2;
    // EBPF_OP_LDXB pc=75 dst=r4 src=r7 offset=34 imm=0
#line 63 "sample/encap_reflect_packet.c"
    r4 = *(uint8_t*)(uintptr_t)(r7 + OFFSET(34));
    // EBPF_OP_LSH64_IMM pc=76 dst=r4 src=r0 offset=0 imm=2
#line 63 "sample/encap_reflect_packet.c"
    r4 <<= (IMMEDIATE(2) & 63);
    // EBPF_OP_AND64_IMM pc=77 dst=r4 src=r0 offset=0 imm=60
#line 63 "sample/encap_reflect_packet.c"
    r4 &= IMMEDIATE(60);
    // EBPF_OP_MOV64_REG pc=78 dst=r2 src=r1 offset=0 imm=0
#line 63 "sample/encap_reflect_packet.c"
    r2 = r1;
    // EBPF_OP_ADD64_REG pc=79 dst=r2 src=r4 offset=0 imm=0
#line 63 "sample/encap_reflect_packet.c"
    r2 += r4;
    // EBPF_OP_MOV64_REG pc=80 dst=r4 src=r2 offset=0 imm=0
#line 64 "sample/encap_reflect_packet.c"
    r4 = r2;
    // EBPF_OP_ADD64_IMM pc=81 dst=r4 src=r0 offset=0 imm=8
#line 64 "sample/encap_reflect_packet.c"
    r4 += IMMEDIATE(8);
    // EBPF_OP_LDXDW pc=82 dst=r5 src=r6 offset=8 imm=0
#line 64 "sample/encap_reflect_packet.c"
    r5 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_JGT_REG pc=83 dst=r4 src=r5 offset=238 imm=0
#line 64 "sample/encap_reflect_packet.c"
    if (r4 > r5)
#line 64 "sample/encap_reflect_packet.c"
        goto label_5;
        // EBPF_OP_LDXH pc=84 dst=r4 src=r2 offset=2 imm=0
#line 68 "sample/encap_reflect_packet.c"
    r4 = *(uint16_t*)(uintptr_t)(r2 + OFFSET(2));
    // EBPF_OP_JNE_IMM pc=85 dst=r4 src=r0 offset=4 imm=7459
#line 68 "sample/encap_reflect_packet.c"
    if (r4 != IMMEDIATE(7459))
#line 68 "sample/encap_reflect_packet.c"
        goto label_1;
        // EBPF_OP_LDXH pc=86 dst=r4 src=r2 offset=0 imm=0
#line 40 "sample/./xdp_common.h"
    r4 = *(uint16_t*)(uintptr_t)(r2 + OFFSET(0));
    // EBPF_OP_STXH pc=87 dst=r2 src=r4 offset=2 imm=0
#line 42 "sample/./xdp_common.h"
    *(uint16_t*)(uintptr_t)(r2 + OFFSET(2)) = (uint16_t)r4;
    // EBPF_OP_MOV64_IMM pc=88 dst=r4 src=r0 offset=0 imm=7459
#line 42 "sample/./xdp_common.h"
    r4 = IMMEDIATE(7459);
    // EBPF_OP_STXH pc=89 dst=r2 src=r4 offset=0 imm=0
#line 41 "sample/./xdp_common.h"
    *(uint16_t*)(uintptr_t)(r2 + OFFSET(0)) = (uint16_t)r4;
label_1:
    // EBPF_OP_LDXW pc=90 dst=r2 src=r1 offset=16 imm=0
#line 73 "sample/encap_reflect_packet.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(16));
    // EBPF_OP_STXW pc=91 dst=r3 src=r2 offset=16 imm=0
#line 73 "sample/encap_reflect_packet.c"
    *(uint32_t*)(uintptr_t)(r3 + OFFSET(16)) = (uint32_t)r2;
    // EBPF_OP_LDXW pc=92 dst=r2 src=r1 offset=12 imm=0
#line 73 "sample/encap_reflect_packet.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(12));
    // EBPF_OP_STXW pc=93 dst=r3 src=r2 offset=12 imm=0
#line 73 "sample/encap_reflect_packet.c"
    *(uint32_t*)(uintptr_t)(r3 + OFFSET(12)) = (uint32_t)r2;
    // EBPF_OP_LDXW pc=94 dst=r2 src=r1 offset=8 imm=0
#line 73 "sample/encap_reflect_packet.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(8));
    // EBPF_OP_STXW pc=95 dst=r3 src=r2 offset=8 imm=0
#line 73 "sample/encap_reflect_packet.c"
    *(uint32_t*)(uintptr_t)(r3 + OFFSET(8)) = (uint32_t)r2;
    // EBPF_OP_LDXW pc=96 dst=r2 src=r1 offset=4 imm=0
#line 73 "sample/encap_reflect_packet.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(4));
    // EBPF_OP_STXW pc=97 dst=r3 src=r2 offset=4 imm=0
#line 73 "sample/encap_reflect_packet.c"
    *(uint32_t*)(uintptr_t)(r3 + OFFSET(4)) = (uint32_t)r2;
    // EBPF_OP_LDXW pc=98 dst=r1 src=r1 offset=0 imm=0
#line 73 "sample/encap_reflect_packet.c"
    r1 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(0));
    // EBPF_OP_STXW pc=99 dst=r3 src=r1 offset=0 imm=0
#line 73 "sample/encap_reflect_packet.c"
    *(uint32_t*)(uintptr_t)(r3 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_IMM pc=100 dst=r1 src=r0 offset=0 imm=4
#line 73 "sample/encap_reflect_packet.c"
    r1 = IMMEDIATE(4);
    // EBPF_OP_STXB pc=101 dst=r7 src=r1 offset=23 imm=0
#line 76 "sample/encap_reflect_packet.c"
    *(uint8_t*)(uintptr_t)(r7 + OFFSET(23)) = (uint8_t)r1;
    // EBPF_OP_LDXB pc=102 dst=r1 src=r7 offset=14 imm=0
#line 77 "sample/encap_reflect_packet.c"
    r1 = *(uint8_t*)(uintptr_t)(r7 + OFFSET(14));
    // EBPF_OP_AND64_IMM pc=103 dst=r1 src=r0 offset=0 imm=240
#line 77 "sample/encap_reflect_packet.c"
    r1 &= IMMEDIATE(240);
    // EBPF_OP_OR64_IMM pc=104 dst=r1 src=r0 offset=0 imm=5
#line 77 "sample/encap_reflect_packet.c"
    r1 |= IMMEDIATE(5);
    // EBPF_OP_STXB pc=105 dst=r7 src=r1 offset=14 imm=0
#line 77 "sample/encap_reflect_packet.c"
    *(uint8_t*)(uintptr_t)(r7 + OFFSET(14)) = (uint8_t)r1;
    // EBPF_OP_LDXH pc=106 dst=r1 src=r7 offset=36 imm=0
#line 78 "sample/encap_reflect_packet.c"
    r1 = *(uint16_t*)(uintptr_t)(r7 + OFFSET(36));
    // EBPF_OP_BE pc=107 dst=r1 src=r0 offset=0 imm=16
#line 78 "sample/encap_reflect_packet.c"
    r1 = htobe16((uint16_t)r1);
#line 78 "sample/encap_reflect_packet.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_ADD64_IMM pc=108 dst=r1 src=r0 offset=0 imm=20
#line 78 "sample/encap_reflect_packet.c"
    r1 += IMMEDIATE(20);
    // EBPF_OP_BE pc=109 dst=r1 src=r0 offset=0 imm=16
#line 78 "sample/encap_reflect_packet.c"
    r1 = htobe16((uint16_t)r1);
#line 78 "sample/encap_reflect_packet.c"
    r1 &= UINT32_MAX;
    // EBPF_OP_STXH pc=110 dst=r7 src=r1 offset=16 imm=0
#line 78 "sample/encap_reflect_packet.c"
    *(uint16_t*)(uintptr_t)(r7 + OFFSET(16)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=111 dst=r1 src=r0 offset=0 imm=0
#line 78 "sample/encap_reflect_packet.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXH pc=112 dst=r7 src=r1 offset=24 imm=0
#line 80 "sample/encap_reflect_packet.c"
    *(uint16_t*)(uintptr_t)(r7 + OFFSET(24)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=113 dst=r1 src=r0 offset=0 imm=0
#line 82 "sample/encap_reflect_packet.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_MOV64_IMM pc=114 dst=r2 src=r0 offset=0 imm=0
#line 82 "sample/encap_reflect_packet.c"
    r2 = IMMEDIATE(0);
    // EBPF_OP_MOV64_IMM pc=115 dst=r4 src=r0 offset=0 imm=20
#line 82 "sample/encap_reflect_packet.c"
    r4 = IMMEDIATE(20);
    // EBPF_OP_MOV64_IMM pc=116 dst=r5 src=r0 offset=0 imm=0
#line 82 "sample/encap_reflect_packet.c"
    r5 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=117 dst=r0 src=r0 offset=0 imm=10
#line 82 "sample/encap_reflect_packet.c"
    r0 = encap_reflect_packet_helpers[1].address
#line 82 "sample/encap_reflect_packet.c"
         (r1, r2, r3, r4, r5);
#line 82 "sample/encap_reflect_packet.c"
    if ((encap_reflect_packet_helpers[1].tail_call) && (r0 == 0))
#line 82 "sample/encap_reflect_packet.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=118 dst=r1 src=r0 offset=0 imm=0
#line 49 "sample/./xdp_common.h"
    r1 = r0;
    // EBPF_OP_AND64_IMM pc=119 dst=r1 src=r0 offset=0 imm=65535
#line 49 "sample/./xdp_common.h"
    r1 &= IMMEDIATE(65535);
    // EBPF_OP_LSH64_IMM pc=120 dst=r0 src=r0 offset=0 imm=32
#line 82 "sample/encap_reflect_packet.c"
    r0 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=121 dst=r0 src=r0 offset=0 imm=48
#line 49 "sample/./xdp_common.h"
    r0 = (int64_t)r0 >> (uint32_t)(IMMEDIATE(48) & 63);
    // EBPF_OP_ADD64_REG pc=122 dst=r0 src=r1 offset=0 imm=0
#line 49 "sample/./xdp_common.h"
    r0 += r1;
    // EBPF_OP_MOV64_REG pc=123 dst=r1 src=r0 offset=0 imm=0
#line 50 "sample/./xdp_common.h"
    r1 = r0;
    // EBPF_OP_RSH64_IMM pc=124 dst=r1 src=r0 offset=0 imm=16
#line 50 "sample/./xdp_common.h"
    r1 >>= (IMMEDIATE(16) & 63);
    // EBPF_OP_ADD64_REG pc=125 dst=r1 src=r0 offset=0 imm=0
#line 50 "sample/./xdp_common.h"
    r1 += r0;
    // EBPF_OP_XOR64_IMM pc=126 dst=r1 src=r0 offset=0 imm=-1
#line 82 "sample/encap_reflect_packet.c"
    r1 ^= IMMEDIATE(-1);
    // EBPF_OP_STXH pc=127 dst=r7 src=r1 offset=24 imm=0
#line 81 "sample/encap_reflect_packet.c"
    *(uint16_t*)(uintptr_t)(r7 + OFFSET(24)) = (uint16_t)r1;
    // EBPF_OP_JA pc=128 dst=r0 src=r0 offset=192 imm=0
#line 81 "sample/encap_reflect_packet.c"
    goto label_4;
label_2:
    // EBPF_OP_MOV64_REG pc=129 dst=r3 src=r2 offset=0 imm=0
#line 196 "sample/encap_reflect_packet.c"
    r3 = r2;
    // EBPF_OP_ADD64_IMM pc=130 dst=r3 src=r0 offset=0 imm=54
#line 196 "sample/encap_reflect_packet.c"
    r3 += IMMEDIATE(54);
    // EBPF_OP_JGT_REG pc=131 dst=r3 src=r1 offset=190 imm=0
#line 196 "sample/encap_reflect_packet.c"
    if (r3 > r1)
#line 196 "sample/encap_reflect_packet.c"
        goto label_5;
        // EBPF_OP_MOV64_REG pc=132 dst=r3 src=r2 offset=0 imm=0
#line 196 "sample/encap_reflect_packet.c"
    r3 = r2;
    // EBPF_OP_ADD64_IMM pc=133 dst=r3 src=r0 offset=0 imm=62
#line 196 "sample/encap_reflect_packet.c"
    r3 += IMMEDIATE(62);
    // EBPF_OP_JGT_REG pc=134 dst=r3 src=r1 offset=187 imm=0
#line 202 "sample/encap_reflect_packet.c"
    if (r3 > r1)
#line 202 "sample/encap_reflect_packet.c"
        goto label_5;
        // EBPF_OP_LDXB pc=135 dst=r1 src=r2 offset=20 imm=0
#line 202 "sample/encap_reflect_packet.c"
    r1 = *(uint8_t*)(uintptr_t)(r2 + OFFSET(20));
    // EBPF_OP_JNE_IMM pc=136 dst=r1 src=r0 offset=185 imm=17
#line 202 "sample/encap_reflect_packet.c"
    if (r1 != IMMEDIATE(17))
#line 202 "sample/encap_reflect_packet.c"
        goto label_5;
        // EBPF_OP_LDXH pc=137 dst=r1 src=r2 offset=56 imm=0
#line 208 "sample/encap_reflect_packet.c"
    r1 = *(uint16_t*)(uintptr_t)(r2 + OFFSET(56));
    // EBPF_OP_JNE_IMM pc=138 dst=r1 src=r0 offset=183 imm=7459
#line 208 "sample/encap_reflect_packet.c"
    if (r1 != IMMEDIATE(7459))
#line 208 "sample/encap_reflect_packet.c"
        goto label_5;
        // EBPF_OP_MOV64_REG pc=139 dst=r1 src=r6 offset=0 imm=0
#line 96 "sample/encap_reflect_packet.c"
    r1 = r6;
    // EBPF_OP_LDDW pc=140 dst=r2 src=r0 offset=0 imm=-40
#line 96 "sample/encap_reflect_packet.c"
    r2 = (uint64_t)4294967256;
    // EBPF_OP_CALL pc=142 dst=r0 src=r0 offset=0 imm=65536
#line 96 "sample/encap_reflect_packet.c"
    r0 = encap_reflect_packet_helpers[0].address
#line 96 "sample/encap_reflect_packet.c"
         (r1, r2, r3, r4, r5);
#line 96 "sample/encap_reflect_packet.c"
    if ((encap_reflect_packet_helpers[0].tail_call) && (r0 == 0))
#line 96 "sample/encap_reflect_packet.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=143 dst=r1 src=r0 offset=0 imm=0
#line 96 "sample/encap_reflect_packet.c"
    r1 = r0;
    // EBPF_OP_MOV64_IMM pc=144 dst=r0 src=r0 offset=0 imm=2
#line 96 "sample/encap_reflect_packet.c"
    r0 = IMMEDIATE(2);
    // EBPF_OP_LSH64_IMM pc=145 dst=r1 src=r0 offset=0 imm=32
#line 96 "sample/encap_reflect_packet.c"
    r1 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=146 dst=r1 src=r0 offset=0 imm=32
#line 96 "sample/encap_reflect_packet.c"
    r1 = (int64_t)r1 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_IMM pc=147 dst=r2 src=r0 offset=0 imm=0
#line 96 "sample/encap_reflect_packet.c"
    r2 = IMMEDIATE(0);
    // EBPF_OP_JSGT_REG pc=148 dst=r2 src=r1 offset=173 imm=0
#line 96 "sample/encap_reflect_packet.c"
    if ((int64_t)r2 > (int64_t)r1)
#line 96 "sample/encap_reflect_packet.c"
        goto label_5;
        // EBPF_OP_LDXDW pc=149 dst=r5 src=r6 offset=8 imm=0
#line 102 "sample/encap_reflect_packet.c"
    r5 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_LDXDW pc=150 dst=r1 src=r6 offset=0 imm=0
#line 101 "sample/encap_reflect_packet.c"
    r1 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(0));
    // EBPF_OP_MOV64_REG pc=151 dst=r2 src=r1 offset=0 imm=0
#line 102 "sample/encap_reflect_packet.c"
    r2 = r1;
    // EBPF_OP_ADD64_IMM pc=152 dst=r2 src=r0 offset=0 imm=14
#line 102 "sample/encap_reflect_packet.c"
    r2 += IMMEDIATE(14);
    // EBPF_OP_JGT_REG pc=153 dst=r2 src=r5 offset=168 imm=0
#line 102 "sample/encap_reflect_packet.c"
    if (r2 > r5)
#line 102 "sample/encap_reflect_packet.c"
        goto label_5;
        // EBPF_OP_MOV64_REG pc=154 dst=r4 src=r1 offset=0 imm=0
#line 109 "sample/encap_reflect_packet.c"
    r4 = r1;
    // EBPF_OP_ADD64_IMM pc=155 dst=r4 src=r0 offset=0 imm=40
#line 109 "sample/encap_reflect_packet.c"
    r4 += IMMEDIATE(40);
    // EBPF_OP_JGT_REG pc=156 dst=r4 src=r5 offset=165 imm=0
#line 109 "sample/encap_reflect_packet.c"
    if (r4 > r5)
#line 109 "sample/encap_reflect_packet.c"
        goto label_5;
        // EBPF_OP_MOV64_REG pc=157 dst=r3 src=r1 offset=0 imm=0
#line 117 "sample/encap_reflect_packet.c"
    r3 = r1;
    // EBPF_OP_ADD64_IMM pc=158 dst=r3 src=r0 offset=0 imm=54
#line 117 "sample/encap_reflect_packet.c"
    r3 += IMMEDIATE(54);
    // EBPF_OP_JGT_REG pc=159 dst=r3 src=r5 offset=162 imm=0
#line 117 "sample/encap_reflect_packet.c"
    if (r3 > r5)
#line 117 "sample/encap_reflect_packet.c"
        goto label_5;
        // EBPF_OP_MOV64_REG pc=160 dst=r7 src=r1 offset=0 imm=0
#line 124 "sample/encap_reflect_packet.c"
    r7 = r1;
    // EBPF_OP_ADD64_IMM pc=161 dst=r7 src=r0 offset=0 imm=94
#line 124 "sample/encap_reflect_packet.c"
    r7 += IMMEDIATE(94);
    // EBPF_OP_JGT_REG pc=162 dst=r7 src=r5 offset=159 imm=0
#line 124 "sample/encap_reflect_packet.c"
    if (r7 > r5)
#line 124 "sample/encap_reflect_packet.c"
        goto label_5;
        // EBPF_OP_LDXH pc=163 dst=r5 src=r4 offset=4 imm=0
#line 130 "sample/encap_reflect_packet.c"
    r5 = *(uint16_t*)(uintptr_t)(r4 + OFFSET(4));
    // EBPF_OP_STXH pc=164 dst=r1 src=r5 offset=4 imm=0
#line 130 "sample/encap_reflect_packet.c"
    *(uint16_t*)(uintptr_t)(r1 + OFFSET(4)) = (uint16_t)r5;
    // EBPF_OP_LDXH pc=165 dst=r5 src=r4 offset=0 imm=0
#line 130 "sample/encap_reflect_packet.c"
    r5 = *(uint16_t*)(uintptr_t)(r4 + OFFSET(0));
    // EBPF_OP_STXH pc=166 dst=r1 src=r5 offset=0 imm=0
#line 130 "sample/encap_reflect_packet.c"
    *(uint16_t*)(uintptr_t)(r1 + OFFSET(0)) = (uint16_t)r5;
    // EBPF_OP_LDXH pc=167 dst=r5 src=r4 offset=2 imm=0
#line 130 "sample/encap_reflect_packet.c"
    r5 = *(uint16_t*)(uintptr_t)(r4 + OFFSET(2));
    // EBPF_OP_STXH pc=168 dst=r1 src=r5 offset=2 imm=0
#line 130 "sample/encap_reflect_packet.c"
    *(uint16_t*)(uintptr_t)(r1 + OFFSET(2)) = (uint16_t)r5;
    // EBPF_OP_LDXH pc=169 dst=r5 src=r4 offset=12 imm=0
#line 130 "sample/encap_reflect_packet.c"
    r5 = *(uint16_t*)(uintptr_t)(r4 + OFFSET(12));
    // EBPF_OP_STXH pc=170 dst=r1 src=r5 offset=12 imm=0
#line 130 "sample/encap_reflect_packet.c"
    *(uint16_t*)(uintptr_t)(r1 + OFFSET(12)) = (uint16_t)r5;
    // EBPF_OP_LDXH pc=171 dst=r5 src=r4 offset=10 imm=0
#line 130 "sample/encap_reflect_packet.c"
    r5 = *(uint16_t*)(uintptr_t)(r4 + OFFSET(10));
    // EBPF_OP_STXH pc=172 dst=r1 src=r5 offset=10 imm=0
#line 130 "sample/encap_reflect_packet.c"
    *(uint16_t*)(uintptr_t)(r1 + OFFSET(10)) = (uint16_t)r5;
    // EBPF_OP_LDXH pc=173 dst=r7 src=r4 offset=8 imm=0
#line 130 "sample/encap_reflect_packet.c"
    r7 = *(uint16_t*)(uintptr_t)(r4 + OFFSET(8));
    // EBPF_OP_LDXH pc=174 dst=r8 src=r4 offset=6 imm=0
#line 130 "sample/encap_reflect_packet.c"
    r8 = *(uint16_t*)(uintptr_t)(r4 + OFFSET(6));
    // EBPF_OP_STXH pc=175 dst=r1 src=r5 offset=4 imm=0
#line 16 "sample/./xdp_common.h"
    *(uint16_t*)(uintptr_t)(r1 + OFFSET(4)) = (uint16_t)r5;
    // EBPF_OP_STXH pc=176 dst=r1 src=r8 offset=6 imm=0
#line 130 "sample/encap_reflect_packet.c"
    *(uint16_t*)(uintptr_t)(r1 + OFFSET(6)) = (uint16_t)r8;
    // EBPF_OP_STXH pc=177 dst=r1 src=r8 offset=0 imm=0
#line 16 "sample/./xdp_common.h"
    *(uint16_t*)(uintptr_t)(r1 + OFFSET(0)) = (uint16_t)r8;
    // EBPF_OP_STXH pc=178 dst=r1 src=r7 offset=8 imm=0
#line 130 "sample/encap_reflect_packet.c"
    *(uint16_t*)(uintptr_t)(r1 + OFFSET(8)) = (uint16_t)r7;
    // EBPF_OP_STXH pc=179 dst=r1 src=r7 offset=2 imm=0
#line 16 "sample/./xdp_common.h"
    *(uint16_t*)(uintptr_t)(r1 + OFFSET(2)) = (uint16_t)r7;
    // EBPF_OP_LDXH pc=180 dst=r5 src=r4 offset=4 imm=0
#line 17 "sample/./xdp_common.h"
    r5 = *(uint16_t*)(uintptr_t)(r4 + OFFSET(4));
    // EBPF_OP_STXH pc=181 dst=r1 src=r5 offset=10 imm=0
#line 17 "sample/./xdp_common.h"
    *(uint16_t*)(uintptr_t)(r1 + OFFSET(10)) = (uint16_t)r5;
    // EBPF_OP_LDXH pc=182 dst=r5 src=r4 offset=0 imm=0
#line 17 "sample/./xdp_common.h"
    r5 = *(uint16_t*)(uintptr_t)(r4 + OFFSET(0));
    // EBPF_OP_STXH pc=183 dst=r1 src=r5 offset=6 imm=0
#line 17 "sample/./xdp_common.h"
    *(uint16_t*)(uintptr_t)(r1 + OFFSET(6)) = (uint16_t)r5;
    // EBPF_OP_LDXH pc=184 dst=r4 src=r4 offset=2 imm=0
#line 17 "sample/./xdp_common.h"
    r4 = *(uint16_t*)(uintptr_t)(r4 + OFFSET(2));
    // EBPF_OP_STXH pc=185 dst=r1 src=r4 offset=8 imm=0
#line 17 "sample/./xdp_common.h"
    *(uint16_t*)(uintptr_t)(r1 + OFFSET(8)) = (uint16_t)r4;
    // EBPF_OP_LDXB pc=186 dst=r5 src=r1 offset=87 imm=0
#line 32 "sample/./xdp_common.h"
    r5 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(87));
    // EBPF_OP_LSH64_IMM pc=187 dst=r5 src=r0 offset=0 imm=8
#line 32 "sample/./xdp_common.h"
    r5 <<= (IMMEDIATE(8) & 63);
    // EBPF_OP_LDXB pc=188 dst=r4 src=r1 offset=86 imm=0
#line 32 "sample/./xdp_common.h"
    r4 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(86));
    // EBPF_OP_OR64_REG pc=189 dst=r5 src=r4 offset=0 imm=0
#line 32 "sample/./xdp_common.h"
    r5 |= r4;
    // EBPF_OP_LDXB pc=190 dst=r4 src=r1 offset=89 imm=0
#line 32 "sample/./xdp_common.h"
    r4 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(89));
    // EBPF_OP_LSH64_IMM pc=191 dst=r4 src=r0 offset=0 imm=8
#line 32 "sample/./xdp_common.h"
    r4 <<= (IMMEDIATE(8) & 63);
    // EBPF_OP_LDXB pc=192 dst=r7 src=r1 offset=88 imm=0
#line 32 "sample/./xdp_common.h"
    r7 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(88));
    // EBPF_OP_OR64_REG pc=193 dst=r4 src=r7 offset=0 imm=0
#line 32 "sample/./xdp_common.h"
    r4 |= r7;
    // EBPF_OP_LSH64_IMM pc=194 dst=r4 src=r0 offset=0 imm=16
#line 32 "sample/./xdp_common.h"
    r4 <<= (IMMEDIATE(16) & 63);
    // EBPF_OP_OR64_REG pc=195 dst=r4 src=r5 offset=0 imm=0
#line 32 "sample/./xdp_common.h"
    r4 |= r5;
    // EBPF_OP_LDXB pc=196 dst=r7 src=r1 offset=91 imm=0
#line 32 "sample/./xdp_common.h"
    r7 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(91));
    // EBPF_OP_LSH64_IMM pc=197 dst=r7 src=r0 offset=0 imm=8
#line 32 "sample/./xdp_common.h"
    r7 <<= (IMMEDIATE(8) & 63);
    // EBPF_OP_LDXB pc=198 dst=r5 src=r1 offset=90 imm=0
#line 32 "sample/./xdp_common.h"
    r5 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(90));
    // EBPF_OP_OR64_REG pc=199 dst=r7 src=r5 offset=0 imm=0
#line 32 "sample/./xdp_common.h"
    r7 |= r5;
    // EBPF_OP_LDXB pc=200 dst=r5 src=r1 offset=93 imm=0
#line 32 "sample/./xdp_common.h"
    r5 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(93));
    // EBPF_OP_LSH64_IMM pc=201 dst=r5 src=r0 offset=0 imm=8
#line 32 "sample/./xdp_common.h"
    r5 <<= (IMMEDIATE(8) & 63);
    // EBPF_OP_LDXB pc=202 dst=r8 src=r1 offset=92 imm=0
#line 32 "sample/./xdp_common.h"
    r8 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(92));
    // EBPF_OP_OR64_REG pc=203 dst=r5 src=r8 offset=0 imm=0
#line 32 "sample/./xdp_common.h"
    r5 |= r8;
    // EBPF_OP_LSH64_IMM pc=204 dst=r5 src=r0 offset=0 imm=16
#line 32 "sample/./xdp_common.h"
    r5 <<= (IMMEDIATE(16) & 63);
    // EBPF_OP_OR64_REG pc=205 dst=r5 src=r7 offset=0 imm=0
#line 32 "sample/./xdp_common.h"
    r5 |= r7;
    // EBPF_OP_LSH64_IMM pc=206 dst=r5 src=r0 offset=0 imm=32
#line 32 "sample/./xdp_common.h"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_OR64_REG pc=207 dst=r5 src=r4 offset=0 imm=0
#line 32 "sample/./xdp_common.h"
    r5 |= r4;
    // EBPF_OP_LDXB pc=208 dst=r7 src=r1 offset=79 imm=0
#line 32 "sample/./xdp_common.h"
    r7 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(79));
    // EBPF_OP_LSH64_IMM pc=209 dst=r7 src=r0 offset=0 imm=8
#line 32 "sample/./xdp_common.h"
    r7 <<= (IMMEDIATE(8) & 63);
    // EBPF_OP_LDXB pc=210 dst=r4 src=r1 offset=78 imm=0
#line 32 "sample/./xdp_common.h"
    r4 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(78));
    // EBPF_OP_OR64_REG pc=211 dst=r7 src=r4 offset=0 imm=0
#line 32 "sample/./xdp_common.h"
    r7 |= r4;
    // EBPF_OP_LDXB pc=212 dst=r4 src=r1 offset=81 imm=0
#line 32 "sample/./xdp_common.h"
    r4 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(81));
    // EBPF_OP_LSH64_IMM pc=213 dst=r4 src=r0 offset=0 imm=8
#line 32 "sample/./xdp_common.h"
    r4 <<= (IMMEDIATE(8) & 63);
    // EBPF_OP_LDXB pc=214 dst=r8 src=r1 offset=80 imm=0
#line 32 "sample/./xdp_common.h"
    r8 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(80));
    // EBPF_OP_OR64_REG pc=215 dst=r4 src=r8 offset=0 imm=0
#line 32 "sample/./xdp_common.h"
    r4 |= r8;
    // EBPF_OP_STXDW pc=216 dst=r10 src=r5 offset=-8 imm=0
#line 32 "sample/./xdp_common.h"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint64_t)r5;
    // EBPF_OP_LSH64_IMM pc=217 dst=r4 src=r0 offset=0 imm=16
#line 32 "sample/./xdp_common.h"
    r4 <<= (IMMEDIATE(16) & 63);
    // EBPF_OP_OR64_REG pc=218 dst=r4 src=r7 offset=0 imm=0
#line 32 "sample/./xdp_common.h"
    r4 |= r7;
    // EBPF_OP_LDXB pc=219 dst=r5 src=r1 offset=83 imm=0
#line 32 "sample/./xdp_common.h"
    r5 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(83));
    // EBPF_OP_LSH64_IMM pc=220 dst=r5 src=r0 offset=0 imm=8
#line 32 "sample/./xdp_common.h"
    r5 <<= (IMMEDIATE(8) & 63);
    // EBPF_OP_LDXB pc=221 dst=r7 src=r1 offset=82 imm=0
#line 32 "sample/./xdp_common.h"
    r7 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(82));
    // EBPF_OP_OR64_REG pc=222 dst=r5 src=r7 offset=0 imm=0
#line 32 "sample/./xdp_common.h"
    r5 |= r7;
    // EBPF_OP_LDXB pc=223 dst=r7 src=r1 offset=85 imm=0
#line 32 "sample/./xdp_common.h"
    r7 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(85));
    // EBPF_OP_LSH64_IMM pc=224 dst=r7 src=r0 offset=0 imm=8
#line 32 "sample/./xdp_common.h"
    r7 <<= (IMMEDIATE(8) & 63);
    // EBPF_OP_LDXB pc=225 dst=r8 src=r1 offset=84 imm=0
#line 32 "sample/./xdp_common.h"
    r8 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(84));
    // EBPF_OP_OR64_REG pc=226 dst=r7 src=r8 offset=0 imm=0
#line 32 "sample/./xdp_common.h"
    r7 |= r8;
    // EBPF_OP_LSH64_IMM pc=227 dst=r7 src=r0 offset=0 imm=16
#line 32 "sample/./xdp_common.h"
    r7 <<= (IMMEDIATE(16) & 63);
    // EBPF_OP_OR64_REG pc=228 dst=r7 src=r5 offset=0 imm=0
#line 32 "sample/./xdp_common.h"
    r7 |= r5;
    // EBPF_OP_LSH64_IMM pc=229 dst=r7 src=r0 offset=0 imm=32
#line 32 "sample/./xdp_common.h"
    r7 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_OR64_REG pc=230 dst=r7 src=r4 offset=0 imm=0
#line 32 "sample/./xdp_common.h"
    r7 |= r4;
    // EBPF_OP_STXDW pc=231 dst=r10 src=r7 offset=-16 imm=0
#line 32 "sample/./xdp_common.h"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r7;
    // EBPF_OP_LDXW pc=232 dst=r4 src=r1 offset=62 imm=0
#line 33 "sample/./xdp_common.h"
    r4 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(62));
    // EBPF_OP_STXW pc=233 dst=r1 src=r4 offset=78 imm=0
#line 33 "sample/./xdp_common.h"
    *(uint32_t*)(uintptr_t)(r1 + OFFSET(78)) = (uint32_t)r4;
    // EBPF_OP_LDXW pc=234 dst=r4 src=r1 offset=66 imm=0
#line 33 "sample/./xdp_common.h"
    r4 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(66));
    // EBPF_OP_STXW pc=235 dst=r1 src=r4 offset=82 imm=0
#line 33 "sample/./xdp_common.h"
    *(uint32_t*)(uintptr_t)(r1 + OFFSET(82)) = (uint32_t)r4;
    // EBPF_OP_LDXW pc=236 dst=r4 src=r1 offset=70 imm=0
#line 33 "sample/./xdp_common.h"
    r4 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(70));
    // EBPF_OP_STXW pc=237 dst=r1 src=r4 offset=86 imm=0
#line 33 "sample/./xdp_common.h"
    *(uint32_t*)(uintptr_t)(r1 + OFFSET(86)) = (uint32_t)r4;
    // EBPF_OP_LDXW pc=238 dst=r4 src=r1 offset=74 imm=0
#line 33 "sample/./xdp_common.h"
    r4 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(74));
    // EBPF_OP_STXW pc=239 dst=r1 src=r4 offset=90 imm=0
#line 33 "sample/./xdp_common.h"
    *(uint32_t*)(uintptr_t)(r1 + OFFSET(90)) = (uint32_t)r4;
    // EBPF_OP_LDXDW pc=240 dst=r4 src=r10 offset=-16 imm=0
#line 34 "sample/./xdp_common.h"
    r4 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=241 dst=r5 src=r4 offset=0 imm=0
#line 34 "sample/./xdp_common.h"
    r5 = r4;
    // EBPF_OP_RSH64_IMM pc=242 dst=r5 src=r0 offset=0 imm=48
#line 34 "sample/./xdp_common.h"
    r5 >>= (IMMEDIATE(48) & 63);
    // EBPF_OP_STXB pc=243 dst=r1 src=r5 offset=68 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(68)) = (uint8_t)r5;
    // EBPF_OP_MOV64_REG pc=244 dst=r5 src=r4 offset=0 imm=0
#line 34 "sample/./xdp_common.h"
    r5 = r4;
    // EBPF_OP_RSH64_IMM pc=245 dst=r5 src=r0 offset=0 imm=56
#line 34 "sample/./xdp_common.h"
    r5 >>= (IMMEDIATE(56) & 63);
    // EBPF_OP_STXB pc=246 dst=r1 src=r5 offset=69 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(69)) = (uint8_t)r5;
    // EBPF_OP_MOV64_REG pc=247 dst=r5 src=r4 offset=0 imm=0
#line 34 "sample/./xdp_common.h"
    r5 = r4;
    // EBPF_OP_RSH64_IMM pc=248 dst=r5 src=r0 offset=0 imm=32
#line 34 "sample/./xdp_common.h"
    r5 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_STXB pc=249 dst=r1 src=r5 offset=66 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(66)) = (uint8_t)r5;
    // EBPF_OP_MOV64_REG pc=250 dst=r5 src=r4 offset=0 imm=0
#line 34 "sample/./xdp_common.h"
    r5 = r4;
    // EBPF_OP_RSH64_IMM pc=251 dst=r5 src=r0 offset=0 imm=40
#line 34 "sample/./xdp_common.h"
    r5 >>= (IMMEDIATE(40) & 63);
    // EBPF_OP_STXB pc=252 dst=r1 src=r5 offset=67 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(67)) = (uint8_t)r5;
    // EBPF_OP_MOV64_REG pc=253 dst=r5 src=r4 offset=0 imm=0
#line 34 "sample/./xdp_common.h"
    r5 = r4;
    // EBPF_OP_RSH64_IMM pc=254 dst=r5 src=r0 offset=0 imm=16
#line 34 "sample/./xdp_common.h"
    r5 >>= (IMMEDIATE(16) & 63);
    // EBPF_OP_STXB pc=255 dst=r1 src=r5 offset=64 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(64)) = (uint8_t)r5;
    // EBPF_OP_MOV64_REG pc=256 dst=r5 src=r4 offset=0 imm=0
#line 34 "sample/./xdp_common.h"
    r5 = r4;
    // EBPF_OP_RSH64_IMM pc=257 dst=r5 src=r0 offset=0 imm=24
#line 34 "sample/./xdp_common.h"
    r5 >>= (IMMEDIATE(24) & 63);
    // EBPF_OP_STXB pc=258 dst=r1 src=r5 offset=65 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(65)) = (uint8_t)r5;
    // EBPF_OP_STXB pc=259 dst=r1 src=r4 offset=62 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(62)) = (uint8_t)r4;
    // EBPF_OP_RSH64_IMM pc=260 dst=r4 src=r0 offset=0 imm=8
#line 34 "sample/./xdp_common.h"
    r4 >>= (IMMEDIATE(8) & 63);
    // EBPF_OP_STXB pc=261 dst=r1 src=r4 offset=63 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(63)) = (uint8_t)r4;
    // EBPF_OP_LDXDW pc=262 dst=r4 src=r10 offset=-8 imm=0
#line 34 "sample/./xdp_common.h"
    r4 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8));
    // EBPF_OP_MOV64_REG pc=263 dst=r5 src=r4 offset=0 imm=0
#line 34 "sample/./xdp_common.h"
    r5 = r4;
    // EBPF_OP_RSH64_IMM pc=264 dst=r5 src=r0 offset=0 imm=48
#line 34 "sample/./xdp_common.h"
    r5 >>= (IMMEDIATE(48) & 63);
    // EBPF_OP_STXB pc=265 dst=r1 src=r5 offset=76 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(76)) = (uint8_t)r5;
    // EBPF_OP_MOV64_REG pc=266 dst=r5 src=r4 offset=0 imm=0
#line 34 "sample/./xdp_common.h"
    r5 = r4;
    // EBPF_OP_RSH64_IMM pc=267 dst=r5 src=r0 offset=0 imm=56
#line 34 "sample/./xdp_common.h"
    r5 >>= (IMMEDIATE(56) & 63);
    // EBPF_OP_STXB pc=268 dst=r1 src=r5 offset=77 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(77)) = (uint8_t)r5;
    // EBPF_OP_MOV64_REG pc=269 dst=r5 src=r4 offset=0 imm=0
#line 34 "sample/./xdp_common.h"
    r5 = r4;
    // EBPF_OP_RSH64_IMM pc=270 dst=r5 src=r0 offset=0 imm=32
#line 34 "sample/./xdp_common.h"
    r5 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_STXB pc=271 dst=r1 src=r5 offset=74 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(74)) = (uint8_t)r5;
    // EBPF_OP_MOV64_REG pc=272 dst=r5 src=r4 offset=0 imm=0
#line 34 "sample/./xdp_common.h"
    r5 = r4;
    // EBPF_OP_RSH64_IMM pc=273 dst=r5 src=r0 offset=0 imm=40
#line 34 "sample/./xdp_common.h"
    r5 >>= (IMMEDIATE(40) & 63);
    // EBPF_OP_STXB pc=274 dst=r1 src=r5 offset=75 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(75)) = (uint8_t)r5;
    // EBPF_OP_MOV64_REG pc=275 dst=r5 src=r4 offset=0 imm=0
#line 34 "sample/./xdp_common.h"
    r5 = r4;
    // EBPF_OP_RSH64_IMM pc=276 dst=r5 src=r0 offset=0 imm=16
#line 34 "sample/./xdp_common.h"
    r5 >>= (IMMEDIATE(16) & 63);
    // EBPF_OP_STXB pc=277 dst=r1 src=r5 offset=72 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(72)) = (uint8_t)r5;
    // EBPF_OP_MOV64_REG pc=278 dst=r5 src=r4 offset=0 imm=0
#line 34 "sample/./xdp_common.h"
    r5 = r4;
    // EBPF_OP_RSH64_IMM pc=279 dst=r5 src=r0 offset=0 imm=24
#line 34 "sample/./xdp_common.h"
    r5 >>= (IMMEDIATE(24) & 63);
    // EBPF_OP_STXB pc=280 dst=r1 src=r5 offset=73 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(73)) = (uint8_t)r5;
    // EBPF_OP_STXB pc=281 dst=r1 src=r4 offset=70 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(70)) = (uint8_t)r4;
    // EBPF_OP_RSH64_IMM pc=282 dst=r4 src=r0 offset=0 imm=8
#line 34 "sample/./xdp_common.h"
    r4 >>= (IMMEDIATE(8) & 63);
    // EBPF_OP_STXB pc=283 dst=r1 src=r4 offset=71 imm=0
#line 34 "sample/./xdp_common.h"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(71)) = (uint8_t)r4;
    // EBPF_OP_MOV64_REG pc=284 dst=r4 src=r1 offset=0 imm=0
#line 138 "sample/encap_reflect_packet.c"
    r4 = r1;
    // EBPF_OP_ADD64_IMM pc=285 dst=r4 src=r0 offset=0 imm=102
#line 138 "sample/encap_reflect_packet.c"
    r4 += IMMEDIATE(102);
    // EBPF_OP_LDXDW pc=286 dst=r5 src=r6 offset=8 imm=0
#line 138 "sample/encap_reflect_packet.c"
    r5 = *(uint64_t*)(uintptr_t)(r6 + OFFSET(8));
    // EBPF_OP_JGT_REG pc=287 dst=r4 src=r5 offset=34 imm=0
#line 138 "sample/encap_reflect_packet.c"
    if (r4 > r5)
#line 138 "sample/encap_reflect_packet.c"
        goto label_5;
        // EBPF_OP_LDXH pc=288 dst=r4 src=r1 offset=96 imm=0
#line 142 "sample/encap_reflect_packet.c"
    r4 = *(uint16_t*)(uintptr_t)(r1 + OFFSET(96));
    // EBPF_OP_JNE_IMM pc=289 dst=r4 src=r0 offset=4 imm=7459
#line 142 "sample/encap_reflect_packet.c"
    if (r4 != IMMEDIATE(7459))
#line 142 "sample/encap_reflect_packet.c"
        goto label_3;
        // EBPF_OP_LDXH pc=290 dst=r4 src=r1 offset=94 imm=0
#line 40 "sample/./xdp_common.h"
    r4 = *(uint16_t*)(uintptr_t)(r1 + OFFSET(94));
    // EBPF_OP_STXH pc=291 dst=r1 src=r4 offset=96 imm=0
#line 42 "sample/./xdp_common.h"
    *(uint16_t*)(uintptr_t)(r1 + OFFSET(96)) = (uint16_t)r4;
    // EBPF_OP_MOV64_IMM pc=292 dst=r4 src=r0 offset=0 imm=7459
#line 42 "sample/./xdp_common.h"
    r4 = IMMEDIATE(7459);
    // EBPF_OP_STXH pc=293 dst=r1 src=r4 offset=94 imm=0
#line 41 "sample/./xdp_common.h"
    *(uint16_t*)(uintptr_t)(r1 + OFFSET(94)) = (uint16_t)r4;
label_3:
    // EBPF_OP_LDXW pc=294 dst=r4 src=r3 offset=36 imm=0
#line 147 "sample/encap_reflect_packet.c"
    r4 = *(uint32_t*)(uintptr_t)(r3 + OFFSET(36));
    // EBPF_OP_STXW pc=295 dst=r2 src=r4 offset=36 imm=0
#line 147 "sample/encap_reflect_packet.c"
    *(uint32_t*)(uintptr_t)(r2 + OFFSET(36)) = (uint32_t)r4;
    // EBPF_OP_LDXW pc=296 dst=r4 src=r3 offset=32 imm=0
#line 147 "sample/encap_reflect_packet.c"
    r4 = *(uint32_t*)(uintptr_t)(r3 + OFFSET(32));
    // EBPF_OP_STXW pc=297 dst=r2 src=r4 offset=32 imm=0
#line 147 "sample/encap_reflect_packet.c"
    *(uint32_t*)(uintptr_t)(r2 + OFFSET(32)) = (uint32_t)r4;
    // EBPF_OP_LDXW pc=298 dst=r4 src=r3 offset=28 imm=0
#line 147 "sample/encap_reflect_packet.c"
    r4 = *(uint32_t*)(uintptr_t)(r3 + OFFSET(28));
    // EBPF_OP_STXW pc=299 dst=r2 src=r4 offset=28 imm=0
#line 147 "sample/encap_reflect_packet.c"
    *(uint32_t*)(uintptr_t)(r2 + OFFSET(28)) = (uint32_t)r4;
    // EBPF_OP_LDXW pc=300 dst=r4 src=r3 offset=24 imm=0
#line 147 "sample/encap_reflect_packet.c"
    r4 = *(uint32_t*)(uintptr_t)(r3 + OFFSET(24));
    // EBPF_OP_STXW pc=301 dst=r2 src=r4 offset=24 imm=0
#line 147 "sample/encap_reflect_packet.c"
    *(uint32_t*)(uintptr_t)(r2 + OFFSET(24)) = (uint32_t)r4;
    // EBPF_OP_LDXW pc=302 dst=r4 src=r3 offset=20 imm=0
#line 147 "sample/encap_reflect_packet.c"
    r4 = *(uint32_t*)(uintptr_t)(r3 + OFFSET(20));
    // EBPF_OP_STXW pc=303 dst=r2 src=r4 offset=20 imm=0
#line 147 "sample/encap_reflect_packet.c"
    *(uint32_t*)(uintptr_t)(r2 + OFFSET(20)) = (uint32_t)r4;
    // EBPF_OP_LDXW pc=304 dst=r4 src=r3 offset=16 imm=0
#line 147 "sample/encap_reflect_packet.c"
    r4 = *(uint32_t*)(uintptr_t)(r3 + OFFSET(16));
    // EBPF_OP_STXW pc=305 dst=r2 src=r4 offset=16 imm=0
#line 147 "sample/encap_reflect_packet.c"
    *(uint32_t*)(uintptr_t)(r2 + OFFSET(16)) = (uint32_t)r4;
    // EBPF_OP_LDXW pc=306 dst=r4 src=r3 offset=12 imm=0
#line 147 "sample/encap_reflect_packet.c"
    r4 = *(uint32_t*)(uintptr_t)(r3 + OFFSET(12));
    // EBPF_OP_STXW pc=307 dst=r2 src=r4 offset=12 imm=0
#line 147 "sample/encap_reflect_packet.c"
    *(uint32_t*)(uintptr_t)(r2 + OFFSET(12)) = (uint32_t)r4;
    // EBPF_OP_LDXW pc=308 dst=r4 src=r3 offset=8 imm=0
#line 147 "sample/encap_reflect_packet.c"
    r4 = *(uint32_t*)(uintptr_t)(r3 + OFFSET(8));
    // EBPF_OP_STXW pc=309 dst=r2 src=r4 offset=8 imm=0
#line 147 "sample/encap_reflect_packet.c"
    *(uint32_t*)(uintptr_t)(r2 + OFFSET(8)) = (uint32_t)r4;
    // EBPF_OP_LDXW pc=310 dst=r4 src=r3 offset=4 imm=0
#line 147 "sample/encap_reflect_packet.c"
    r4 = *(uint32_t*)(uintptr_t)(r3 + OFFSET(4));
    // EBPF_OP_STXW pc=311 dst=r2 src=r4 offset=4 imm=0
#line 147 "sample/encap_reflect_packet.c"
    *(uint32_t*)(uintptr_t)(r2 + OFFSET(4)) = (uint32_t)r4;
    // EBPF_OP_LDXW pc=312 dst=r3 src=r3 offset=0 imm=0
#line 147 "sample/encap_reflect_packet.c"
    r3 = *(uint32_t*)(uintptr_t)(r3 + OFFSET(0));
    // EBPF_OP_STXW pc=313 dst=r2 src=r3 offset=0 imm=0
#line 147 "sample/encap_reflect_packet.c"
    *(uint32_t*)(uintptr_t)(r2 + OFFSET(0)) = (uint32_t)r3;
    // EBPF_OP_MOV64_IMM pc=314 dst=r2 src=r0 offset=0 imm=41
#line 147 "sample/encap_reflect_packet.c"
    r2 = IMMEDIATE(41);
    // EBPF_OP_STXB pc=315 dst=r1 src=r2 offset=20 imm=0
#line 150 "sample/encap_reflect_packet.c"
    *(uint8_t*)(uintptr_t)(r1 + OFFSET(20)) = (uint8_t)r2;
    // EBPF_OP_LDXH pc=316 dst=r2 src=r1 offset=58 imm=0
#line 151 "sample/encap_reflect_packet.c"
    r2 = *(uint16_t*)(uintptr_t)(r1 + OFFSET(58));
    // EBPF_OP_BE pc=317 dst=r2 src=r0 offset=0 imm=16
#line 151 "sample/encap_reflect_packet.c"
    r2 = htobe16((uint16_t)r2);
#line 151 "sample/encap_reflect_packet.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_ADD64_IMM pc=318 dst=r2 src=r0 offset=0 imm=40
#line 151 "sample/encap_reflect_packet.c"
    r2 += IMMEDIATE(40);
    // EBPF_OP_BE pc=319 dst=r2 src=r0 offset=0 imm=16
#line 151 "sample/encap_reflect_packet.c"
    r2 = htobe16((uint16_t)r2);
#line 151 "sample/encap_reflect_packet.c"
    r2 &= UINT32_MAX;
    // EBPF_OP_STXH pc=320 dst=r1 src=r2 offset=18 imm=0
#line 151 "sample/encap_reflect_packet.c"
    *(uint16_t*)(uintptr_t)(r1 + OFFSET(18)) = (uint16_t)r2;
label_4:
    // EBPF_OP_MOV64_IMM pc=321 dst=r0 src=r0 offset=0 imm=3
#line 151 "sample/encap_reflect_packet.c"
    r0 = IMMEDIATE(3);
label_5:
    // EBPF_OP_EXIT pc=322 dst=r0 src=r0 offset=0 imm=0
#line 216 "sample/encap_reflect_packet.c"
    return r0;
#line 216 "sample/encap_reflect_packet.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        encap_reflect_packet,
        "xdp_te~1",
        "xdp_test/encap_reflect",
        "encap_reflect_packet",
        NULL,
        0,
        encap_reflect_packet_helpers,
        2,
        323,
        &encap_reflect_packet_program_type_guid,
        &encap_reflect_packet_attach_type_guid,
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
    version->minor = 16;
    version->revision = 0;
}

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = NULL;
    *count = 0;
}

metadata_table_t encap_reflect_packet_metadata_table = {
    sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version, _get_map_initial_values};
