// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from printk.o

#define NO_CRT
#include "bpf2c.h"

#include <guiddef.h>
#include <wdm.h>
#include <wsk.h>

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
RTL_QUERY_REGISTRY_ROUTINE static _bpf2c_query_registry_routine;

#define metadata_table printk##_metadata_table

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

static helper_function_entry_t func_helpers[] = {
    {NULL, 12, "helper_id_12"},
    {NULL, 19, "helper_id_19"},
    {NULL, 13, "helper_id_13"},
    {NULL, 14, "helper_id_14"},
    {NULL, 15, "helper_id_15"},
};

static GUID func_program_type_guid = {0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID func_attach_type_guid = {0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
#pragma code_seg(push, "bind")
static uint64_t
func(void* context)
#line 18 "sample/printk.c"
{
#line 18 "sample/printk.c"
    // Prologue
#line 18 "sample/printk.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 18 "sample/printk.c"
    register uint64_t r0 = 0;
#line 18 "sample/printk.c"
    register uint64_t r1 = 0;
#line 18 "sample/printk.c"
    register uint64_t r2 = 0;
#line 18 "sample/printk.c"
    register uint64_t r3 = 0;
#line 18 "sample/printk.c"
    register uint64_t r4 = 0;
#line 18 "sample/printk.c"
    register uint64_t r5 = 0;
#line 18 "sample/printk.c"
    register uint64_t r6 = 0;
#line 18 "sample/printk.c"
    register uint64_t r7 = 0;
#line 18 "sample/printk.c"
    register uint64_t r8 = 0;
#line 18 "sample/printk.c"
    register uint64_t r9 = 0;
#line 18 "sample/printk.c"
    register uint64_t r10 = 0;

#line 18 "sample/printk.c"
    r1 = (uintptr_t)context;
#line 18 "sample/printk.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r7 src=r1 offset=0 imm=0
#line 18 "sample/printk.c"
    r7 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=0
#line 18 "sample/printk.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=2 dst=r10 src=r1 offset=-20 imm=0
#line 23 "sample/printk.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-20)) = (uint8_t)r1;
    // EBPF_OP_MOV64_IMM pc=3 dst=r6 src=r0 offset=0 imm=1684828783
#line 23 "sample/printk.c"
    r6 = IMMEDIATE(1684828783);
    // EBPF_OP_STXW pc=4 dst=r10 src=r6 offset=-24 imm=0
#line 23 "sample/printk.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r6;
    // EBPF_OP_LDDW pc=5 dst=r8 src=r0 offset=0 imm=1819043144
#line 23 "sample/printk.c"
    r8 = (uint64_t)8583909746840200520;
    // EBPF_OP_STXDW pc=7 dst=r10 src=r8 offset=-32 imm=0
#line 23 "sample/printk.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r8;
    // EBPF_OP_MOV64_REG pc=8 dst=r1 src=r10 offset=0 imm=0
#line 23 "sample/printk.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=9 dst=r1 src=r0 offset=0 imm=-32
#line 23 "sample/printk.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=10 dst=r2 src=r0 offset=0 imm=13
#line 23 "sample/printk.c"
    r2 = IMMEDIATE(13);
    // EBPF_OP_CALL pc=11 dst=r0 src=r0 offset=0 imm=12
#line 23 "sample/printk.c"
    r0 = func_helpers[0].address
#line 23 "sample/printk.c"
         (r1, r2, r3, r4, r5);
#line 23 "sample/printk.c"
    if ((func_helpers[0].tail_call) && (r0 == 0))
#line 23 "sample/printk.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=12 dst=r9 src=r0 offset=0 imm=0
#line 23 "sample/printk.c"
    r9 = r0;
    // EBPF_OP_MOV64_IMM pc=13 dst=r1 src=r0 offset=0 imm=10
#line 23 "sample/printk.c"
    r1 = IMMEDIATE(10);
    // EBPF_OP_STXH pc=14 dst=r10 src=r1 offset=-20 imm=0
#line 24 "sample/printk.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-20)) = (uint16_t)r1;
    // EBPF_OP_STXW pc=15 dst=r10 src=r6 offset=-24 imm=0
#line 24 "sample/printk.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r6;
    // EBPF_OP_STXDW pc=16 dst=r10 src=r8 offset=-32 imm=0
#line 24 "sample/printk.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r8;
    // EBPF_OP_MOV64_REG pc=17 dst=r1 src=r10 offset=0 imm=0
#line 24 "sample/printk.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=18 dst=r1 src=r0 offset=0 imm=-32
#line 24 "sample/printk.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=19 dst=r2 src=r0 offset=0 imm=14
#line 24 "sample/printk.c"
    r2 = IMMEDIATE(14);
    // EBPF_OP_CALL pc=20 dst=r0 src=r0 offset=0 imm=12
#line 24 "sample/printk.c"
    r0 = func_helpers[0].address
#line 24 "sample/printk.c"
         (r1, r2, r3, r4, r5);
#line 24 "sample/printk.c"
    if ((func_helpers[0].tail_call) && (r0 == 0))
#line 24 "sample/printk.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=21 dst=r6 src=r0 offset=0 imm=0
#line 24 "sample/printk.c"
    r6 = r0;
    // EBPF_OP_CALL pc=22 dst=r0 src=r0 offset=0 imm=19
#line 27 "sample/printk.c"
    r0 = func_helpers[1].address
#line 27 "sample/printk.c"
         (r1, r2, r3, r4, r5);
#line 27 "sample/printk.c"
    if ((func_helpers[1].tail_call) && (r0 == 0))
#line 27 "sample/printk.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=23 dst=r8 src=r0 offset=0 imm=0
#line 27 "sample/printk.c"
    r8 = r0;
    // EBPF_OP_LDDW pc=24 dst=r1 src=r0 offset=0 imm=1852404597
#line 27 "sample/printk.c"
    r1 = (uint64_t)2676581182147752821;
    // EBPF_OP_STXDW pc=26 dst=r10 src=r1 offset=-24 imm=0
#line 28 "sample/printk.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_ADD64_REG pc=27 dst=r6 src=r9 offset=0 imm=0
#line 24 "sample/printk.c"
    r6 += r9;
    // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=117
#line 24 "sample/printk.c"
    r1 = IMMEDIATE(117);
    // EBPF_OP_STXH pc=29 dst=r10 src=r1 offset=-16 imm=0
#line 28 "sample/printk.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=30 dst=r9 src=r0 offset=0 imm=117
#line 28 "sample/printk.c"
    r9 = IMMEDIATE(117);
    // EBPF_OP_LDDW pc=31 dst=r1 src=r0 offset=0 imm=977553744
#line 28 "sample/printk.c"
    r1 = (uint64_t)2338816401835575632;
    // EBPF_OP_STXDW pc=33 dst=r10 src=r1 offset=-32 imm=0
#line 28 "sample/printk.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_RSH64_IMM pc=34 dst=r8 src=r0 offset=0 imm=32
#line 28 "sample/printk.c"
    r8 >>= IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=35 dst=r1 src=r10 offset=0 imm=0
#line 28 "sample/printk.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=36 dst=r1 src=r0 offset=0 imm=-32
#line 28 "sample/printk.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=37 dst=r2 src=r0 offset=0 imm=18
#line 28 "sample/printk.c"
    r2 = IMMEDIATE(18);
    // EBPF_OP_MOV64_REG pc=38 dst=r3 src=r8 offset=0 imm=0
#line 28 "sample/printk.c"
    r3 = r8;
    // EBPF_OP_CALL pc=39 dst=r0 src=r0 offset=0 imm=13
#line 28 "sample/printk.c"
    r0 = func_helpers[2].address
#line 28 "sample/printk.c"
         (r1, r2, r3, r4, r5);
#line 28 "sample/printk.c"
    if ((func_helpers[2].tail_call) && (r0 == 0))
#line 28 "sample/printk.c"
        return 0;
    // EBPF_OP_MOV64_IMM pc=40 dst=r1 src=r0 offset=0 imm=7695397
#line 28 "sample/printk.c"
    r1 = IMMEDIATE(7695397);
    // EBPF_OP_STXW pc=41 dst=r10 src=r1 offset=-16 imm=0
#line 29 "sample/printk.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=42 dst=r1 src=r0 offset=0 imm=1769174304
#line 29 "sample/printk.c"
    r1 = (uint64_t)2675251902571312416;
    // EBPF_OP_STXDW pc=44 dst=r10 src=r1 offset=-24 imm=0
#line 29 "sample/printk.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=45 dst=r1 src=r0 offset=0 imm=977553744
#line 29 "sample/printk.c"
    r1 = (uint64_t)8461178620269054288;
    // EBPF_OP_STXDW pc=47 dst=r10 src=r1 offset=-32 imm=0
#line 29 "sample/printk.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_ADD64_REG pc=48 dst=r6 src=r0 offset=0 imm=0
#line 28 "sample/printk.c"
    r6 += r0;
    // EBPF_OP_MOV64_REG pc=49 dst=r1 src=r10 offset=0 imm=0
#line 28 "sample/printk.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=50 dst=r1 src=r0 offset=0 imm=-32
#line 28 "sample/printk.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=51 dst=r2 src=r0 offset=0 imm=20
#line 29 "sample/printk.c"
    r2 = IMMEDIATE(20);
    // EBPF_OP_MOV64_REG pc=52 dst=r3 src=r8 offset=0 imm=0
#line 29 "sample/printk.c"
    r3 = r8;
    // EBPF_OP_CALL pc=53 dst=r0 src=r0 offset=0 imm=13
#line 29 "sample/printk.c"
    r0 = func_helpers[2].address
#line 29 "sample/printk.c"
         (r1, r2, r3, r4, r5);
#line 29 "sample/printk.c"
    if ((func_helpers[2].tail_call) && (r0 == 0))
#line 29 "sample/printk.c"
        return 0;
    // EBPF_OP_MOV64_IMM pc=54 dst=r1 src=r0 offset=0 imm=1819026725
#line 29 "sample/printk.c"
    r1 = IMMEDIATE(1819026725);
    // EBPF_OP_STXW pc=55 dst=r10 src=r1 offset=-16 imm=0
#line 30 "sample/printk.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=56 dst=r1 src=r0 offset=0 imm=1937055861
#line 30 "sample/printk.c"
    r1 = (uint64_t)2334956331002568821;
    // EBPF_OP_STXDW pc=58 dst=r10 src=r1 offset=-24 imm=0
#line 30 "sample/printk.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=59 dst=r1 src=r0 offset=0 imm=977553744
#line 30 "sample/printk.c"
    r1 = (uint64_t)7812660273927702864;
    // EBPF_OP_STXDW pc=61 dst=r10 src=r1 offset=-32 imm=0
#line 30 "sample/printk.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_ADD64_REG pc=62 dst=r6 src=r0 offset=0 imm=0
#line 29 "sample/printk.c"
    r6 += r0;
    // EBPF_OP_STXH pc=63 dst=r10 src=r9 offset=-12 imm=0
#line 30 "sample/printk.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-12)) = (uint16_t)r9;
    // EBPF_OP_MOV64_REG pc=64 dst=r1 src=r10 offset=0 imm=0
#line 30 "sample/printk.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=65 dst=r1 src=r0 offset=0 imm=-32
#line 30 "sample/printk.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=66 dst=r2 src=r0 offset=0 imm=22
#line 30 "sample/printk.c"
    r2 = IMMEDIATE(22);
    // EBPF_OP_MOV64_REG pc=67 dst=r3 src=r8 offset=0 imm=0
#line 30 "sample/printk.c"
    r3 = r8;
    // EBPF_OP_CALL pc=68 dst=r0 src=r0 offset=0 imm=13
#line 30 "sample/printk.c"
    r0 = func_helpers[2].address
#line 30 "sample/printk.c"
         (r1, r2, r3, r4, r5);
#line 30 "sample/printk.c"
    if ((func_helpers[2].tail_call) && (r0 == 0))
#line 30 "sample/printk.c"
        return 0;
    // EBPF_OP_ADD64_REG pc=69 dst=r6 src=r0 offset=0 imm=0
#line 30 "sample/printk.c"
    r6 += r0;
    // EBPF_OP_STXH pc=70 dst=r10 src=r9 offset=-16 imm=0
#line 31 "sample/printk.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint16_t)r9;
    // EBPF_OP_LDDW pc=71 dst=r8 src=r0 offset=0 imm=1414484560
#line 31 "sample/printk.c"
    r8 = (uint64_t)2675202291049386576;
    // EBPF_OP_STXDW pc=73 dst=r10 src=r8 offset=-24 imm=0
#line 31 "sample/printk.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r8;
    // EBPF_OP_LDDW pc=74 dst=r9 src=r0 offset=0 imm=977553744
#line 31 "sample/printk.c"
    r9 = (uint64_t)2338816401835575632;
    // EBPF_OP_STXDW pc=76 dst=r10 src=r9 offset=-32 imm=0
#line 31 "sample/printk.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r9;
    // EBPF_OP_LDXB pc=77 dst=r4 src=r7 offset=48 imm=0
#line 31 "sample/printk.c"
    r4 = *(uint8_t*)(uintptr_t)(r7 + OFFSET(48));
    // EBPF_OP_LDXDW pc=78 dst=r3 src=r7 offset=16 imm=0
#line 31 "sample/printk.c"
    r3 = *(uint64_t*)(uintptr_t)(r7 + OFFSET(16));
    // EBPF_OP_MOV64_REG pc=79 dst=r1 src=r10 offset=0 imm=0
#line 31 "sample/printk.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=80 dst=r1 src=r0 offset=0 imm=-32
#line 31 "sample/printk.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=81 dst=r2 src=r0 offset=0 imm=18
#line 31 "sample/printk.c"
    r2 = IMMEDIATE(18);
    // EBPF_OP_CALL pc=82 dst=r0 src=r0 offset=0 imm=14
#line 31 "sample/printk.c"
    r0 = func_helpers[3].address
#line 31 "sample/printk.c"
         (r1, r2, r3, r4, r5);
#line 31 "sample/printk.c"
    if ((func_helpers[3].tail_call) && (r0 == 0))
#line 31 "sample/printk.c"
        return 0;
    // EBPF_OP_MOV64_IMM pc=83 dst=r1 src=r0 offset=0 imm=117
#line 33 "sample/printk.c"
    r1 = IMMEDIATE(117);
    // EBPF_OP_STXH pc=84 dst=r10 src=r1 offset=-4 imm=0
#line 33 "sample/printk.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=85 dst=r1 src=r0 offset=0 imm=622869070
#line 33 "sample/printk.c"
    r1 = IMMEDIATE(622869070);
    // EBPF_OP_STXW pc=86 dst=r10 src=r1 offset=-8 imm=0
#line 33 "sample/printk.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=87 dst=r1 src=r0 offset=0 imm=1145118837
#line 33 "sample/printk.c"
    r1 = (uint64_t)4993456540003410037;
    // EBPF_OP_STXDW pc=89 dst=r10 src=r1 offset=-16 imm=0
#line 33 "sample/printk.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_STXDW pc=90 dst=r10 src=r8 offset=-24 imm=0
#line 33 "sample/printk.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r8;
    // EBPF_OP_STXDW pc=91 dst=r10 src=r9 offset=-32 imm=0
#line 33 "sample/printk.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r9;
    // EBPF_OP_ADD64_REG pc=92 dst=r6 src=r0 offset=0 imm=0
#line 31 "sample/printk.c"
    r6 += r0;
    // EBPF_OP_LDXB pc=93 dst=r5 src=r7 offset=40 imm=0
#line 33 "sample/printk.c"
    r5 = *(uint8_t*)(uintptr_t)(r7 + OFFSET(40));
    // EBPF_OP_LDXB pc=94 dst=r4 src=r7 offset=48 imm=0
#line 33 "sample/printk.c"
    r4 = *(uint8_t*)(uintptr_t)(r7 + OFFSET(48));
    // EBPF_OP_LDXDW pc=95 dst=r3 src=r7 offset=16 imm=0
#line 33 "sample/printk.c"
    r3 = *(uint64_t*)(uintptr_t)(r7 + OFFSET(16));
    // EBPF_OP_MOV64_REG pc=96 dst=r1 src=r10 offset=0 imm=0
#line 33 "sample/printk.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=97 dst=r1 src=r0 offset=0 imm=-32
#line 33 "sample/printk.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=98 dst=r2 src=r0 offset=0 imm=30
#line 33 "sample/printk.c"
    r2 = IMMEDIATE(30);
    // EBPF_OP_CALL pc=99 dst=r0 src=r0 offset=0 imm=15
#line 33 "sample/printk.c"
    r0 = func_helpers[4].address
#line 33 "sample/printk.c"
         (r1, r2, r3, r4, r5);
#line 33 "sample/printk.c"
    if ((func_helpers[4].tail_call) && (r0 == 0))
#line 33 "sample/printk.c"
        return 0;
    // EBPF_OP_MOV64_IMM pc=100 dst=r1 src=r0 offset=0 imm=9504
#line 33 "sample/printk.c"
    r1 = IMMEDIATE(9504);
    // EBPF_OP_STXH pc=101 dst=r10 src=r1 offset=-28 imm=0
#line 37 "sample/printk.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-28)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=102 dst=r1 src=r0 offset=0 imm=826556738
#line 37 "sample/printk.c"
    r1 = IMMEDIATE(826556738);
    // EBPF_OP_STXW pc=103 dst=r10 src=r1 offset=-32 imm=0
#line 37 "sample/printk.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint32_t)r1;
    // EBPF_OP_ADD64_REG pc=104 dst=r6 src=r0 offset=0 imm=0
#line 32 "sample/printk.c"
    r6 += r0;
    // EBPF_OP_MOV64_IMM pc=105 dst=r8 src=r0 offset=0 imm=0
#line 32 "sample/printk.c"
    r8 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=106 dst=r10 src=r8 offset=-26 imm=0
#line 37 "sample/printk.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-26)) = (uint8_t)r8;
    // EBPF_OP_MOV64_REG pc=107 dst=r1 src=r10 offset=0 imm=0
#line 37 "sample/printk.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=108 dst=r1 src=r0 offset=0 imm=-32
#line 37 "sample/printk.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=109 dst=r2 src=r0 offset=0 imm=7
#line 37 "sample/printk.c"
    r2 = IMMEDIATE(7);
    // EBPF_OP_CALL pc=110 dst=r0 src=r0 offset=0 imm=12
#line 37 "sample/printk.c"
    r0 = func_helpers[0].address
#line 37 "sample/printk.c"
         (r1, r2, r3, r4, r5);
#line 37 "sample/printk.c"
    if ((func_helpers[0].tail_call) && (r0 == 0))
#line 37 "sample/printk.c"
        return 0;
    // EBPF_OP_LDDW pc=111 dst=r1 src=r0 offset=0 imm=843333954
#line 37 "sample/printk.c"
    r1 = (uint64_t)7812660273793483074;
    // EBPF_OP_STXDW pc=113 dst=r10 src=r1 offset=-32 imm=0
#line 38 "sample/printk.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_ADD64_REG pc=114 dst=r6 src=r0 offset=0 imm=0
#line 37 "sample/printk.c"
    r6 += r0;
    // EBPF_OP_STXB pc=115 dst=r10 src=r8 offset=-24 imm=0
#line 38 "sample/printk.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint8_t)r8;
    // EBPF_OP_MOV64_IMM pc=116 dst=r8 src=r0 offset=0 imm=0
#line 38 "sample/printk.c"
    r8 = IMMEDIATE(0);
    // EBPF_OP_MOV64_REG pc=117 dst=r1 src=r10 offset=0 imm=0
#line 38 "sample/printk.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=118 dst=r1 src=r0 offset=0 imm=-32
#line 38 "sample/printk.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=119 dst=r2 src=r0 offset=0 imm=9
#line 38 "sample/printk.c"
    r2 = IMMEDIATE(9);
    // EBPF_OP_CALL pc=120 dst=r0 src=r0 offset=0 imm=12
#line 38 "sample/printk.c"
    r0 = func_helpers[0].address
#line 38 "sample/printk.c"
         (r1, r2, r3, r4, r5);
#line 38 "sample/printk.c"
    if ((func_helpers[0].tail_call) && (r0 == 0))
#line 38 "sample/printk.c"
        return 0;
    // EBPF_OP_LDDW pc=121 dst=r1 src=r0 offset=0 imm=860111170
#line 38 "sample/printk.c"
    r1 = (uint64_t)7220718397787750722;
    // EBPF_OP_STXDW pc=123 dst=r10 src=r1 offset=-32 imm=0
#line 39 "sample/printk.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_ADD64_REG pc=124 dst=r6 src=r0 offset=0 imm=0
#line 38 "sample/printk.c"
    r6 += r0;
    // EBPF_OP_STXB pc=125 dst=r10 src=r8 offset=-24 imm=0
#line 39 "sample/printk.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint8_t)r8;
    // EBPF_OP_LDXDW pc=126 dst=r3 src=r7 offset=16 imm=0
#line 39 "sample/printk.c"
    r3 = *(uint64_t*)(uintptr_t)(r7 + OFFSET(16));
    // EBPF_OP_MOV64_REG pc=127 dst=r1 src=r10 offset=0 imm=0
#line 39 "sample/printk.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=128 dst=r1 src=r0 offset=0 imm=-32
#line 39 "sample/printk.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=129 dst=r2 src=r0 offset=0 imm=9
#line 39 "sample/printk.c"
    r2 = IMMEDIATE(9);
    // EBPF_OP_CALL pc=130 dst=r0 src=r0 offset=0 imm=13
#line 39 "sample/printk.c"
    r0 = func_helpers[2].address
#line 39 "sample/printk.c"
         (r1, r2, r3, r4, r5);
#line 39 "sample/printk.c"
    if ((func_helpers[2].tail_call) && (r0 == 0))
#line 39 "sample/printk.c"
        return 0;
    // EBPF_OP_LDDW pc=131 dst=r1 src=r0 offset=0 imm=876888386
#line 39 "sample/printk.c"
    r1 = (uint64_t)31566017637663042;
    // EBPF_OP_STXDW pc=133 dst=r10 src=r1 offset=-32 imm=0
#line 40 "sample/printk.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_ADD64_REG pc=134 dst=r6 src=r0 offset=0 imm=0
#line 39 "sample/printk.c"
    r6 += r0;
    // EBPF_OP_LDXDW pc=135 dst=r3 src=r7 offset=16 imm=0
#line 40 "sample/printk.c"
    r3 = *(uint64_t*)(uintptr_t)(r7 + OFFSET(16));
    // EBPF_OP_MOV64_REG pc=136 dst=r1 src=r10 offset=0 imm=0
#line 40 "sample/printk.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=137 dst=r1 src=r0 offset=0 imm=-32
#line 40 "sample/printk.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=138 dst=r2 src=r0 offset=0 imm=8
#line 40 "sample/printk.c"
    r2 = IMMEDIATE(8);
    // EBPF_OP_CALL pc=139 dst=r0 src=r0 offset=0 imm=13
#line 40 "sample/printk.c"
    r0 = func_helpers[2].address
#line 40 "sample/printk.c"
         (r1, r2, r3, r4, r5);
#line 40 "sample/printk.c"
    if ((func_helpers[2].tail_call) && (r0 == 0))
#line 40 "sample/printk.c"
        return 0;
    // EBPF_OP_MOV64_IMM pc=140 dst=r1 src=r0 offset=0 imm=893665602
#line 40 "sample/printk.c"
    r1 = IMMEDIATE(893665602);
    // EBPF_OP_STXW pc=141 dst=r10 src=r1 offset=-32 imm=0
#line 44 "sample/printk.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint32_t)r1;
    // EBPF_OP_ADD64_REG pc=142 dst=r6 src=r0 offset=0 imm=0
#line 40 "sample/printk.c"
    r6 += r0;
    // EBPF_OP_STXB pc=143 dst=r10 src=r8 offset=-28 imm=0
#line 44 "sample/printk.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-28)) = (uint8_t)r8;
    // EBPF_OP_LDXDW pc=144 dst=r3 src=r7 offset=16 imm=0
#line 44 "sample/printk.c"
    r3 = *(uint64_t*)(uintptr_t)(r7 + OFFSET(16));
    // EBPF_OP_MOV64_REG pc=145 dst=r1 src=r10 offset=0 imm=0
#line 44 "sample/printk.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=146 dst=r1 src=r0 offset=0 imm=-32
#line 44 "sample/printk.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=147 dst=r2 src=r0 offset=0 imm=5
#line 44 "sample/printk.c"
    r2 = IMMEDIATE(5);
    // EBPF_OP_CALL pc=148 dst=r0 src=r0 offset=0 imm=13
#line 44 "sample/printk.c"
    r0 = func_helpers[2].address
#line 44 "sample/printk.c"
         (r1, r2, r3, r4, r5);
#line 44 "sample/printk.c"
    if ((func_helpers[2].tail_call) && (r0 == 0))
#line 44 "sample/printk.c"
        return 0;
    // EBPF_OP_LDDW pc=149 dst=r1 src=r0 offset=0 imm=910442818
#line 44 "sample/printk.c"
    r1 = (uint64_t)32973392554770754;
    // EBPF_OP_STXDW pc=151 dst=r10 src=r1 offset=-32 imm=0
#line 45 "sample/printk.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_ADD64_REG pc=152 dst=r6 src=r0 offset=0 imm=0
#line 44 "sample/printk.c"
    r6 += r0;
    // EBPF_OP_MOV64_REG pc=153 dst=r1 src=r10 offset=0 imm=0
#line 44 "sample/printk.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=154 dst=r1 src=r0 offset=0 imm=-32
#line 44 "sample/printk.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=155 dst=r2 src=r0 offset=0 imm=8
#line 45 "sample/printk.c"
    r2 = IMMEDIATE(8);
    // EBPF_OP_CALL pc=156 dst=r0 src=r0 offset=0 imm=12
#line 45 "sample/printk.c"
    r0 = func_helpers[0].address
#line 45 "sample/printk.c"
         (r1, r2, r3, r4, r5);
#line 45 "sample/printk.c"
    if ((func_helpers[0].tail_call) && (r0 == 0))
#line 45 "sample/printk.c"
        return 0;
    // EBPF_OP_STXB pc=157 dst=r10 src=r8 offset=-22 imm=0
#line 48 "sample/printk.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-22)) = (uint8_t)r8;
    // EBPF_OP_MOV64_IMM pc=158 dst=r1 src=r0 offset=0 imm=25966
#line 48 "sample/printk.c"
    r1 = IMMEDIATE(25966);
    // EBPF_OP_STXH pc=159 dst=r10 src=r1 offset=-24 imm=0
#line 48 "sample/printk.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=160 dst=r1 src=r0 offset=0 imm=623915057
#line 48 "sample/printk.c"
    r1 = (uint64_t)8026575779790860337;
    // EBPF_OP_STXDW pc=162 dst=r10 src=r1 offset=-32 imm=0
#line 48 "sample/printk.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_ADD64_REG pc=163 dst=r6 src=r0 offset=0 imm=0
#line 45 "sample/printk.c"
    r6 += r0;
    // EBPF_OP_MOV64_REG pc=164 dst=r1 src=r10 offset=0 imm=0
#line 45 "sample/printk.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=165 dst=r1 src=r0 offset=0 imm=-32
#line 45 "sample/printk.c"
    r1 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=166 dst=r2 src=r0 offset=0 imm=11
#line 48 "sample/printk.c"
    r2 = IMMEDIATE(11);
    // EBPF_OP_CALL pc=167 dst=r0 src=r0 offset=0 imm=12
#line 48 "sample/printk.c"
    r0 = func_helpers[0].address
#line 48 "sample/printk.c"
         (r1, r2, r3, r4, r5);
#line 48 "sample/printk.c"
    if ((func_helpers[0].tail_call) && (r0 == 0))
#line 48 "sample/printk.c"
        return 0;
    // EBPF_OP_ADD64_REG pc=168 dst=r6 src=r0 offset=0 imm=0
#line 48 "sample/printk.c"
    r6 += r0;
    // EBPF_OP_MOV64_REG pc=169 dst=r0 src=r6 offset=0 imm=0
#line 50 "sample/printk.c"
    r0 = r6;
    // EBPF_OP_EXIT pc=170 dst=r0 src=r0 offset=0 imm=0
#line 50 "sample/printk.c"
    return r0;
#line 50 "sample/printk.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        func,
        "bind",
        "bind",
        "func",
        NULL,
        0,
        func_helpers,
        5,
        171,
        &func_program_type_guid,
        &func_attach_type_guid,
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

metadata_table_t printk_metadata_table = {sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version};
