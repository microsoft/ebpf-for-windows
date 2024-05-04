// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from utility.o

#define NO_CRT
#include "bpf2c.h"

#include <guiddef.h>
#include <wdm.h>
#include <wsk.h>

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
RTL_QUERY_REGISTRY_ROUTINE static _bpf2c_query_registry_routine;

#define metadata_table utility##_metadata_table

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

static helper_function_entry_t UtilityTest_helpers[] = {
    {NULL, 23, "helper_id_23"},
    {NULL, 22, "helper_id_22"},
    {NULL, 24, "helper_id_24"},
    {NULL, 25, "helper_id_25"},
};

static GUID UtilityTest_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID UtilityTest_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
#pragma code_seg(push, "bind")
static uint64_t
UtilityTest(void* context)
#line 24 "sample/utility.c"
{
#line 24 "sample/utility.c"
    // Prologue
#line 24 "sample/utility.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 24 "sample/utility.c"
    register uint64_t r0 = 0;
#line 24 "sample/utility.c"
    register uint64_t r1 = 0;
#line 24 "sample/utility.c"
    register uint64_t r2 = 0;
#line 24 "sample/utility.c"
    register uint64_t r3 = 0;
#line 24 "sample/utility.c"
    register uint64_t r4 = 0;
#line 24 "sample/utility.c"
    register uint64_t r5 = 0;
#line 24 "sample/utility.c"
    register uint64_t r6 = 0;
#line 24 "sample/utility.c"
    register uint64_t r10 = 0;

#line 24 "sample/utility.c"
    r1 = (uintptr_t)context;
#line 24 "sample/utility.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r1 src=r0 offset=0 imm=0
#line 24 "sample/utility.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=1 dst=r10 src=r1 offset=-4 imm=0
#line 26 "sample/utility.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint8_t)r1;
    // EBPF_OP_MOV64_IMM pc=2 dst=r2 src=r0 offset=0 imm=1953719668
#line 26 "sample/utility.c"
    r2 = IMMEDIATE(1953719668);
    // EBPF_OP_STXW pc=3 dst=r10 src=r2 offset=-8 imm=0
#line 26 "sample/utility.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r2;
    // EBPF_OP_STXW pc=4 dst=r10 src=r2 offset=-16 imm=0
#line 27 "sample/utility.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r2;
    // EBPF_OP_STXB pc=5 dst=r10 src=r1 offset=-12 imm=0
#line 27 "sample/utility.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-12)) = (uint8_t)r1;
    // EBPF_OP_STXB pc=6 dst=r10 src=r1 offset=-22 imm=0
#line 28 "sample/utility.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-22)) = (uint8_t)r1;
    // EBPF_OP_MOV64_IMM pc=7 dst=r1 src=r0 offset=0 imm=12345
#line 28 "sample/utility.c"
    r1 = IMMEDIATE(12345);
    // EBPF_OP_STXH pc=8 dst=r10 src=r1 offset=-24 imm=0
#line 28 "sample/utility.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=9 dst=r1 src=r0 offset=0 imm=875770417
#line 28 "sample/utility.c"
    r1 = (uint64_t)4050765991979987505;
    // EBPF_OP_STXDW pc=11 dst=r10 src=r1 offset=-32 imm=0
#line 28 "sample/utility.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=12 dst=r1 src=r10 offset=0 imm=0
#line 28 "sample/utility.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=13 dst=r1 src=r0 offset=0 imm=-8
#line 28 "sample/utility.c"
    r1 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_REG pc=14 dst=r3 src=r10 offset=0 imm=0
#line 28 "sample/utility.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=15 dst=r3 src=r0 offset=0 imm=-16
#line 28 "sample/utility.c"
    r3 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_IMM pc=16 dst=r2 src=r0 offset=0 imm=4
#line 31 "sample/utility.c"
    r2 = IMMEDIATE(4);
    // EBPF_OP_MOV64_IMM pc=17 dst=r4 src=r0 offset=0 imm=4
#line 31 "sample/utility.c"
    r4 = IMMEDIATE(4);
    // EBPF_OP_CALL pc=18 dst=r0 src=r0 offset=0 imm=23
#line 31 "sample/utility.c"
    r0 = UtilityTest_helpers[0].address
#line 31 "sample/utility.c"
         (r1, r2, r3, r4, r5);
#line 31 "sample/utility.c"
    if ((UtilityTest_helpers[0].tail_call) && (r0 == 0))
#line 31 "sample/utility.c"
        return 0;
        // EBPF_OP_MOV64_IMM pc=19 dst=r6 src=r0 offset=0 imm=1
#line 31 "sample/utility.c"
    r6 = IMMEDIATE(1);
    // EBPF_OP_LSH64_IMM pc=20 dst=r0 src=r0 offset=0 imm=32
#line 31 "sample/utility.c"
    r0 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_RSH64_IMM pc=21 dst=r0 src=r0 offset=0 imm=32
#line 31 "sample/utility.c"
    r0 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JNE_IMM pc=22 dst=r0 src=r0 offset=83 imm=0
#line 31 "sample/utility.c"
    if (r0 != IMMEDIATE(0))
#line 31 "sample/utility.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=23 dst=r1 src=r0 offset=0 imm=84
#line 31 "sample/utility.c"
    r1 = IMMEDIATE(84);
    // EBPF_OP_STXB pc=24 dst=r10 src=r1 offset=-8 imm=0
#line 35 "sample/utility.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r1;
    // EBPF_OP_MOV64_REG pc=25 dst=r1 src=r10 offset=0 imm=0
#line 35 "sample/utility.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=26 dst=r1 src=r0 offset=0 imm=-8
#line 35 "sample/utility.c"
    r1 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_REG pc=27 dst=r3 src=r10 offset=0 imm=0
#line 35 "sample/utility.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=28 dst=r3 src=r0 offset=0 imm=-16
#line 35 "sample/utility.c"
    r3 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_IMM pc=29 dst=r2 src=r0 offset=0 imm=4
#line 37 "sample/utility.c"
    r2 = IMMEDIATE(4);
    // EBPF_OP_MOV64_IMM pc=30 dst=r4 src=r0 offset=0 imm=4
#line 37 "sample/utility.c"
    r4 = IMMEDIATE(4);
    // EBPF_OP_CALL pc=31 dst=r0 src=r0 offset=0 imm=23
#line 37 "sample/utility.c"
    r0 = UtilityTest_helpers[0].address
#line 37 "sample/utility.c"
         (r1, r2, r3, r4, r5);
#line 37 "sample/utility.c"
    if ((UtilityTest_helpers[0].tail_call) && (r0 == 0))
#line 37 "sample/utility.c"
        return 0;
        // EBPF_OP_MOV64_IMM pc=32 dst=r6 src=r0 offset=0 imm=2
#line 37 "sample/utility.c"
    r6 = IMMEDIATE(2);
    // EBPF_OP_LSH64_IMM pc=33 dst=r0 src=r0 offset=0 imm=32
#line 37 "sample/utility.c"
    r0 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=34 dst=r0 src=r0 offset=0 imm=32
#line 37 "sample/utility.c"
    r0 = (int64_t)r0 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=35 dst=r0 src=r0 offset=70 imm=-1
#line 37 "sample/utility.c"
    if ((int64_t)r0 > IMMEDIATE(-1))
#line 37 "sample/utility.c"
        goto label_1;
        // EBPF_OP_MOV64_REG pc=36 dst=r1 src=r10 offset=0 imm=0
#line 37 "sample/utility.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=37 dst=r1 src=r0 offset=0 imm=-8
#line 43 "sample/utility.c"
    r1 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_IMM pc=38 dst=r6 src=r0 offset=0 imm=3
#line 43 "sample/utility.c"
    r6 = IMMEDIATE(3);
    // EBPF_OP_MOV64_REG pc=39 dst=r3 src=r10 offset=0 imm=0
#line 43 "sample/utility.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=40 dst=r3 src=r0 offset=0 imm=-16
#line 43 "sample/utility.c"
    r3 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_IMM pc=41 dst=r2 src=r0 offset=0 imm=3
#line 43 "sample/utility.c"
    r2 = IMMEDIATE(3);
    // EBPF_OP_MOV64_IMM pc=42 dst=r4 src=r0 offset=0 imm=4
#line 43 "sample/utility.c"
    r4 = IMMEDIATE(4);
    // EBPF_OP_CALL pc=43 dst=r0 src=r0 offset=0 imm=23
#line 43 "sample/utility.c"
    r0 = UtilityTest_helpers[0].address
#line 43 "sample/utility.c"
         (r1, r2, r3, r4, r5);
#line 43 "sample/utility.c"
    if ((UtilityTest_helpers[0].tail_call) && (r0 == 0))
#line 43 "sample/utility.c"
        return 0;
        // EBPF_OP_LSH64_IMM pc=44 dst=r0 src=r0 offset=0 imm=32
#line 43 "sample/utility.c"
    r0 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=45 dst=r0 src=r0 offset=0 imm=32
#line 43 "sample/utility.c"
    r0 = (int64_t)r0 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=46 dst=r0 src=r0 offset=59 imm=-1
#line 43 "sample/utility.c"
    if ((int64_t)r0 > IMMEDIATE(-1))
#line 43 "sample/utility.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=47 dst=r1 src=r0 offset=0 imm=1414743380
#line 43 "sample/utility.c"
    r1 = IMMEDIATE(1414743380);
    // EBPF_OP_STXW pc=48 dst=r10 src=r1 offset=-8 imm=0
#line 48 "sample/utility.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=49 dst=r1 src=r10 offset=0 imm=0
#line 48 "sample/utility.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=50 dst=r1 src=r0 offset=0 imm=-8
#line 48 "sample/utility.c"
    r1 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_REG pc=51 dst=r3 src=r10 offset=0 imm=0
#line 48 "sample/utility.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=52 dst=r3 src=r0 offset=0 imm=-16
#line 48 "sample/utility.c"
    r3 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_IMM pc=53 dst=r2 src=r0 offset=0 imm=4
#line 54 "sample/utility.c"
    r2 = IMMEDIATE(4);
    // EBPF_OP_MOV64_IMM pc=54 dst=r4 src=r0 offset=0 imm=4
#line 54 "sample/utility.c"
    r4 = IMMEDIATE(4);
    // EBPF_OP_CALL pc=55 dst=r0 src=r0 offset=0 imm=22
#line 54 "sample/utility.c"
    r0 = UtilityTest_helpers[1].address
#line 54 "sample/utility.c"
         (r1, r2, r3, r4, r5);
#line 54 "sample/utility.c"
    if ((UtilityTest_helpers[1].tail_call) && (r0 == 0))
#line 54 "sample/utility.c"
        return 0;
        // EBPF_OP_MOV64_IMM pc=56 dst=r1 src=r0 offset=0 imm=0
#line 54 "sample/utility.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_MOV64_IMM pc=57 dst=r6 src=r0 offset=0 imm=4
#line 54 "sample/utility.c"
    r6 = IMMEDIATE(4);
    // EBPF_OP_JSGT_REG pc=58 dst=r1 src=r0 offset=47 imm=0
#line 54 "sample/utility.c"
    if ((int64_t)r1 > (int64_t)r0)
#line 54 "sample/utility.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=59 dst=r6 src=r0 offset=0 imm=5
#line 54 "sample/utility.c"
    r6 = IMMEDIATE(5);
    // EBPF_OP_LDXB pc=60 dst=r1 src=r10 offset=-8 imm=0
#line 59 "sample/utility.c"
    r1 = *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8));
    // EBPF_OP_JNE_IMM pc=61 dst=r1 src=r0 offset=44 imm=116
#line 59 "sample/utility.c"
    if (r1 != IMMEDIATE(116))
#line 59 "sample/utility.c"
        goto label_1;
        // EBPF_OP_LDXB pc=62 dst=r1 src=r10 offset=-7 imm=0
#line 59 "sample/utility.c"
    r1 = *(uint8_t*)(uintptr_t)(r10 + OFFSET(-7));
    // EBPF_OP_JNE_IMM pc=63 dst=r1 src=r0 offset=42 imm=101
#line 59 "sample/utility.c"
    if (r1 != IMMEDIATE(101))
#line 59 "sample/utility.c"
        goto label_1;
        // EBPF_OP_LDXB pc=64 dst=r1 src=r10 offset=-6 imm=0
#line 59 "sample/utility.c"
    r1 = *(uint8_t*)(uintptr_t)(r10 + OFFSET(-6));
    // EBPF_OP_JNE_IMM pc=65 dst=r1 src=r0 offset=40 imm=115
#line 59 "sample/utility.c"
    if (r1 != IMMEDIATE(115))
#line 59 "sample/utility.c"
        goto label_1;
        // EBPF_OP_LDXB pc=66 dst=r1 src=r10 offset=-5 imm=0
#line 59 "sample/utility.c"
    r1 = *(uint8_t*)(uintptr_t)(r10 + OFFSET(-5));
    // EBPF_OP_JNE_IMM pc=67 dst=r1 src=r0 offset=38 imm=116
#line 59 "sample/utility.c"
    if (r1 != IMMEDIATE(116))
#line 59 "sample/utility.c"
        goto label_1;
        // EBPF_OP_MOV64_REG pc=68 dst=r1 src=r10 offset=0 imm=0
#line 59 "sample/utility.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=69 dst=r1 src=r0 offset=0 imm=-8
#line 64 "sample/utility.c"
    r1 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_IMM pc=70 dst=r2 src=r0 offset=0 imm=4
#line 64 "sample/utility.c"
    r2 = IMMEDIATE(4);
    // EBPF_OP_MOV64_IMM pc=71 dst=r3 src=r0 offset=0 imm=0
#line 64 "sample/utility.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=72 dst=r0 src=r0 offset=0 imm=24
#line 64 "sample/utility.c"
    r0 = UtilityTest_helpers[2].address
#line 64 "sample/utility.c"
         (r1, r2, r3, r4, r5);
#line 64 "sample/utility.c"
    if ((UtilityTest_helpers[2].tail_call) && (r0 == 0))
#line 64 "sample/utility.c"
        return 0;
        // EBPF_OP_MOV64_IMM pc=73 dst=r6 src=r0 offset=0 imm=6
#line 64 "sample/utility.c"
    r6 = IMMEDIATE(6);
    // EBPF_OP_JEQ_IMM pc=74 dst=r0 src=r0 offset=31 imm=0
#line 64 "sample/utility.c"
    if (r0 == IMMEDIATE(0))
#line 64 "sample/utility.c"
        goto label_1;
        // EBPF_OP_LDXB pc=75 dst=r1 src=r10 offset=-8 imm=0
#line 69 "sample/utility.c"
    r1 = *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8));
    // EBPF_OP_LDXB pc=76 dst=r2 src=r10 offset=-7 imm=0
#line 69 "sample/utility.c"
    r2 = *(uint8_t*)(uintptr_t)(r10 + OFFSET(-7));
    // EBPF_OP_OR64_REG pc=77 dst=r2 src=r1 offset=0 imm=0
#line 69 "sample/utility.c"
    r2 |= r1;
    // EBPF_OP_LDXB pc=78 dst=r1 src=r10 offset=-6 imm=0
#line 69 "sample/utility.c"
    r1 = *(uint8_t*)(uintptr_t)(r10 + OFFSET(-6));
    // EBPF_OP_OR64_REG pc=79 dst=r2 src=r1 offset=0 imm=0
#line 69 "sample/utility.c"
    r2 |= r1;
    // EBPF_OP_LDXB pc=80 dst=r1 src=r10 offset=-5 imm=0
#line 69 "sample/utility.c"
    r1 = *(uint8_t*)(uintptr_t)(r10 + OFFSET(-5));
    // EBPF_OP_OR64_REG pc=81 dst=r2 src=r1 offset=0 imm=0
#line 69 "sample/utility.c"
    r2 |= r1;
    // EBPF_OP_MOV64_IMM pc=82 dst=r6 src=r0 offset=0 imm=7
#line 69 "sample/utility.c"
    r6 = IMMEDIATE(7);
    // EBPF_OP_AND64_IMM pc=83 dst=r2 src=r0 offset=0 imm=255
#line 69 "sample/utility.c"
    r2 &= IMMEDIATE(255);
    // EBPF_OP_JNE_IMM pc=84 dst=r2 src=r0 offset=21 imm=0
#line 69 "sample/utility.c"
    if (r2 != IMMEDIATE(0))
#line 69 "sample/utility.c"
        goto label_1;
        // EBPF_OP_MOV64_REG pc=85 dst=r1 src=r10 offset=0 imm=0
#line 74 "sample/utility.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=86 dst=r1 src=r0 offset=0 imm=-30
#line 74 "sample/utility.c"
    r1 += IMMEDIATE(-30);
    // EBPF_OP_MOV64_REG pc=87 dst=r3 src=r10 offset=0 imm=0
#line 74 "sample/utility.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=88 dst=r3 src=r0 offset=0 imm=-32
#line 74 "sample/utility.c"
    r3 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=89 dst=r2 src=r0 offset=0 imm=4
#line 74 "sample/utility.c"
    r2 = IMMEDIATE(4);
    // EBPF_OP_MOV64_IMM pc=90 dst=r4 src=r0 offset=0 imm=4
#line 74 "sample/utility.c"
    r4 = IMMEDIATE(4);
    // EBPF_OP_CALL pc=91 dst=r0 src=r0 offset=0 imm=25
#line 74 "sample/utility.c"
    r0 = UtilityTest_helpers[3].address
#line 74 "sample/utility.c"
         (r1, r2, r3, r4, r5);
#line 74 "sample/utility.c"
    if ((UtilityTest_helpers[3].tail_call) && (r0 == 0))
#line 74 "sample/utility.c"
        return 0;
        // EBPF_OP_MOV64_IMM pc=92 dst=r6 src=r0 offset=0 imm=8
#line 74 "sample/utility.c"
    r6 = IMMEDIATE(8);
    // EBPF_OP_MOV64_IMM pc=93 dst=r1 src=r0 offset=0 imm=0
#line 74 "sample/utility.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_JSGT_REG pc=94 dst=r1 src=r0 offset=11 imm=0
#line 74 "sample/utility.c"
    if ((int64_t)r1 > (int64_t)r0)
#line 74 "sample/utility.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=95 dst=r6 src=r0 offset=0 imm=9
#line 74 "sample/utility.c"
    r6 = IMMEDIATE(9);
    // EBPF_OP_LDXB pc=96 dst=r1 src=r10 offset=-30 imm=0
#line 79 "sample/utility.c"
    r1 = *(uint8_t*)(uintptr_t)(r10 + OFFSET(-30));
    // EBPF_OP_JNE_IMM pc=97 dst=r1 src=r0 offset=8 imm=49
#line 79 "sample/utility.c"
    if (r1 != IMMEDIATE(49))
#line 79 "sample/utility.c"
        goto label_1;
        // EBPF_OP_LDXB pc=98 dst=r1 src=r10 offset=-29 imm=0
#line 79 "sample/utility.c"
    r1 = *(uint8_t*)(uintptr_t)(r10 + OFFSET(-29));
    // EBPF_OP_JNE_IMM pc=99 dst=r1 src=r0 offset=6 imm=50
#line 79 "sample/utility.c"
    if (r1 != IMMEDIATE(50))
#line 79 "sample/utility.c"
        goto label_1;
        // EBPF_OP_LDXB pc=100 dst=r1 src=r10 offset=-28 imm=0
#line 79 "sample/utility.c"
    r1 = *(uint8_t*)(uintptr_t)(r10 + OFFSET(-28));
    // EBPF_OP_JNE_IMM pc=101 dst=r1 src=r0 offset=4 imm=51
#line 79 "sample/utility.c"
    if (r1 != IMMEDIATE(51))
#line 79 "sample/utility.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=102 dst=r6 src=r0 offset=0 imm=0
#line 79 "sample/utility.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_LDXB pc=103 dst=r1 src=r10 offset=-27 imm=0
#line 79 "sample/utility.c"
    r1 = *(uint8_t*)(uintptr_t)(r10 + OFFSET(-27));
    // EBPF_OP_JEQ_IMM pc=104 dst=r1 src=r0 offset=1 imm=52
#line 79 "sample/utility.c"
    if (r1 == IMMEDIATE(52))
#line 79 "sample/utility.c"
        goto label_1;
        // EBPF_OP_MOV64_IMM pc=105 dst=r6 src=r0 offset=0 imm=9
#line 79 "sample/utility.c"
    r6 = IMMEDIATE(9);
label_1:
    // EBPF_OP_MOV64_REG pc=106 dst=r0 src=r6 offset=0 imm=0
#line 84 "sample/utility.c"
    r0 = r6;
    // EBPF_OP_EXIT pc=107 dst=r0 src=r0 offset=0 imm=0
#line 84 "sample/utility.c"
    return r0;
#line 84 "sample/utility.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        UtilityTest,
        "bind",
        "bind",
        "UtilityTest",
        NULL,
        0,
        UtilityTest_helpers,
        4,
        108,
        &UtilityTest_program_type_guid,
        &UtilityTest_attach_type_guid,
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

metadata_table_t utility_metadata_table = {
    sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version, _get_map_initial_values};
