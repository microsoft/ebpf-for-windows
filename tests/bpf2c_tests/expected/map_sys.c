// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from map.o

#define NO_CRT
#include "bpf2c.h"

#include <guiddef.h>
#include <wdm.h>
#include <wsk.h>

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
RTL_QUERY_REGISTRY_ROUTINE static _bpf2c_query_registry_routine;

#define metadata_table map##_metadata_table

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
         4,                 // Size in bytes of a map key.
         4,                 // Size in bytes of a map value.
         10,                // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         PIN_NONE,          // Pinning type for the map.
         0,                 // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "HASH_map"},
    {NULL,
     {
         BPF_MAP_TYPE_PERCPU_HASH, // Type of map.
         4,                        // Size in bytes of a map key.
         4,                        // Size in bytes of a map value.
         10,                       // Maximum number of entries allowed in the map.
         0,                        // Inner map index.
         PIN_NONE,                 // Pinning type for the map.
         0,                        // Identifier for a map template.
         0,                        // The id of the inner map template.
     },
     "PERCPU_HASH_map"},
    {NULL,
     {
         BPF_MAP_TYPE_ARRAY, // Type of map.
         4,                  // Size in bytes of a map key.
         4,                  // Size in bytes of a map value.
         10,                 // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         PIN_NONE,           // Pinning type for the map.
         0,                  // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "ARRAY_map"},
    {NULL,
     {
         BPF_MAP_TYPE_PERCPU_ARRAY, // Type of map.
         4,                         // Size in bytes of a map key.
         4,                         // Size in bytes of a map value.
         10,                        // Maximum number of entries allowed in the map.
         0,                         // Inner map index.
         PIN_NONE,                  // Pinning type for the map.
         0,                         // Identifier for a map template.
         0,                         // The id of the inner map template.
     },
     "PERCPU_ARRAY_map"},
    {NULL,
     {
         BPF_MAP_TYPE_LRU_HASH, // Type of map.
         4,                     // Size in bytes of a map key.
         4,                     // Size in bytes of a map value.
         10,                    // Maximum number of entries allowed in the map.
         0,                     // Inner map index.
         PIN_NONE,              // Pinning type for the map.
         0,                     // Identifier for a map template.
         0,                     // The id of the inner map template.
     },
     "LRU_HASH_map"},
    {NULL,
     {
         BPF_MAP_TYPE_LRU_PERCPU_HASH, // Type of map.
         4,                            // Size in bytes of a map key.
         4,                            // Size in bytes of a map value.
         10,                           // Maximum number of entries allowed in the map.
         0,                            // Inner map index.
         PIN_NONE,                     // Pinning type for the map.
         0,                            // Identifier for a map template.
         0,                            // The id of the inner map template.
     },
     "LRU_PERCPU_HASH_map"},
    {NULL,
     {
         BPF_MAP_TYPE_QUEUE, // Type of map.
         0,                  // Size in bytes of a map key.
         4,                  // Size in bytes of a map value.
         10,                 // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         PIN_NONE,           // Pinning type for the map.
         0,                  // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "QUEUE_map"},
    {NULL,
     {
         BPF_MAP_TYPE_STACK, // Type of map.
         0,                  // Size in bytes of a map key.
         4,                  // Size in bytes of a map value.
         10,                 // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         PIN_NONE,           // Pinning type for the map.
         0,                  // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "STACK_map"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 8;
}

static helper_function_entry_t test_maps_helpers[] = {
    {NULL, 2, "helper_id_2"},
    {NULL, 1, "helper_id_1"},
    {NULL, 3, "helper_id_3"},
    {NULL, 4, "helper_id_4"},
    {NULL, 18, "helper_id_18"},
    {NULL, 17, "helper_id_17"},
    {NULL, 16, "helper_id_16"},
};

static GUID test_maps_program_type_guid = {
    0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};
static GUID test_maps_attach_type_guid = {0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
static uint16_t test_maps_maps[] = {
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
};

#pragma code_seg(push, "xdp_prog")
static uint64_t
test_maps(void* context)
#line 292 "sample/map.c"
{
#line 292 "sample/map.c"
    // Prologue
#line 292 "sample/map.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 292 "sample/map.c"
    register uint64_t r0 = 0;
#line 292 "sample/map.c"
    register uint64_t r1 = 0;
#line 292 "sample/map.c"
    register uint64_t r2 = 0;
#line 292 "sample/map.c"
    register uint64_t r3 = 0;
#line 292 "sample/map.c"
    register uint64_t r4 = 0;
#line 292 "sample/map.c"
    register uint64_t r5 = 0;
#line 292 "sample/map.c"
    register uint64_t r6 = 0;
#line 292 "sample/map.c"
    register uint64_t r7 = 0;
#line 292 "sample/map.c"
    register uint64_t r8 = 0;
#line 292 "sample/map.c"
    register uint64_t r10 = 0;

#line 292 "sample/map.c"
    r1 = (uintptr_t)context;
#line 292 "sample/map.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r7 src=r0 offset=0 imm=0
#line 292 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1 dst=r10 src=r7 offset=-4 imm=0
#line 72 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_IMM pc=2 dst=r1 src=r0 offset=0 imm=1
#line 72 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=3 dst=r10 src=r1 offset=-8 imm=0
#line 73 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=4 dst=r2 src=r10 offset=0 imm=0
#line 73 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=5 dst=r2 src=r0 offset=0 imm=-4
#line 73 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=6 dst=r3 src=r10 offset=0 imm=0
#line 73 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=7 dst=r3 src=r0 offset=0 imm=-8
#line 73 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=8 dst=r1 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=10 dst=r4 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=11 dst=r0 src=r0 offset=0 imm=2
#line 76 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 76 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 76 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 76 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=12 dst=r6 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=13 dst=r6 src=r0 offset=0 imm=32
#line 76 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=14 dst=r6 src=r0 offset=0 imm=32
#line 76 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_REG pc=15 dst=r7 src=r6 offset=30 imm=0
#line 77 "sample/map.c"
    if ((int64_t)r7 > (int64_t)r6)
#line 77 "sample/map.c"
        goto label_1;
    // EBPF_OP_MOV64_REG pc=16 dst=r2 src=r10 offset=0 imm=0
#line 77 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=17 dst=r2 src=r0 offset=0 imm=-4
#line 77 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=18 dst=r1 src=r0 offset=0 imm=0
#line 82 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=20 dst=r0 src=r0 offset=0 imm=1
#line 82 "sample/map.c"
    r0 = test_maps_helpers[1].address
#line 82 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 82 "sample/map.c"
    if ((test_maps_helpers[1].tail_call) && (r0 == 0))
#line 82 "sample/map.c"
        return 0;
    // EBPF_OP_LDDW pc=21 dst=r6 src=r0 offset=0 imm=-1
#line 82 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JEQ_IMM pc=23 dst=r0 src=r0 offset=22 imm=0
#line 83 "sample/map.c"
    if (r0 == IMMEDIATE(0))
#line 83 "sample/map.c"
        goto label_1;
    // EBPF_OP_MOV64_REG pc=24 dst=r2 src=r10 offset=0 imm=0
#line 83 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=25 dst=r2 src=r0 offset=0 imm=-4
#line 83 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=26 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=28 dst=r0 src=r0 offset=0 imm=3
#line 88 "sample/map.c"
    r0 = test_maps_helpers[2].address
#line 88 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 88 "sample/map.c"
    if ((test_maps_helpers[2].tail_call) && (r0 == 0))
#line 88 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=29 dst=r6 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=30 dst=r6 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=31 dst=r6 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_IMM pc=32 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_JSGT_REG pc=33 dst=r1 src=r6 offset=12 imm=0
#line 89 "sample/map.c"
    if ((int64_t)r1 > (int64_t)r6)
#line 89 "sample/map.c"
        goto label_1;
    // EBPF_OP_MOV64_REG pc=34 dst=r2 src=r10 offset=0 imm=0
#line 89 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=35 dst=r2 src=r0 offset=0 imm=-4
#line 89 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=36 dst=r3 src=r10 offset=0 imm=0
#line 89 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=37 dst=r3 src=r0 offset=0 imm=-8
#line 89 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=38 dst=r1 src=r0 offset=0 imm=0
#line 94 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=40 dst=r4 src=r0 offset=0 imm=0
#line 94 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=41 dst=r0 src=r0 offset=0 imm=2
#line 94 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 94 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 94 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 94 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=42 dst=r6 src=r0 offset=0 imm=0
#line 94 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=43 dst=r6 src=r0 offset=0 imm=32
#line 94 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=44 dst=r6 src=r0 offset=0 imm=32
#line 94 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=45 dst=r6 src=r0 offset=2 imm=-1
#line 95 "sample/map.c"
    if ((int64_t)r6 > IMMEDIATE(-1))
#line 95 "sample/map.c"
        goto label_2;
label_1:
    // EBPF_OP_MOV64_REG pc=46 dst=r0 src=r6 offset=0 imm=0
#line 308 "sample/map.c"
    r0 = r6;
    // EBPF_OP_EXIT pc=47 dst=r0 src=r0 offset=0 imm=0
#line 308 "sample/map.c"
    return r0;
label_2:
    // EBPF_OP_MOV64_REG pc=48 dst=r2 src=r10 offset=0 imm=0
#line 308 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=49 dst=r2 src=r0 offset=0 imm=-4
#line 308 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=50 dst=r1 src=r0 offset=0 imm=0
#line 105 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=52 dst=r0 src=r0 offset=0 imm=4
#line 105 "sample/map.c"
    r0 = test_maps_helpers[3].address
#line 105 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 105 "sample/map.c"
    if ((test_maps_helpers[3].tail_call) && (r0 == 0))
#line 105 "sample/map.c"
        return 0;
    // EBPF_OP_LDDW pc=53 dst=r6 src=r0 offset=0 imm=-1
#line 105 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JEQ_IMM pc=55 dst=r0 src=r0 offset=-10 imm=0
#line 295 "sample/map.c"
    if (r0 == IMMEDIATE(0))
#line 295 "sample/map.c"
        goto label_1;
    // EBPF_OP_MOV64_IMM pc=56 dst=r7 src=r0 offset=0 imm=0
#line 295 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=57 dst=r10 src=r7 offset=-4 imm=0
#line 72 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_IMM pc=58 dst=r1 src=r0 offset=0 imm=1
#line 72 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=59 dst=r10 src=r1 offset=-8 imm=0
#line 73 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=60 dst=r2 src=r10 offset=0 imm=0
#line 73 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=61 dst=r2 src=r0 offset=0 imm=-4
#line 73 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=62 dst=r3 src=r10 offset=0 imm=0
#line 73 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=63 dst=r3 src=r0 offset=0 imm=-8
#line 73 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=64 dst=r1 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_MOV64_IMM pc=66 dst=r4 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=67 dst=r0 src=r0 offset=0 imm=2
#line 76 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 76 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 76 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 76 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=68 dst=r6 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=69 dst=r6 src=r0 offset=0 imm=32
#line 76 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=70 dst=r6 src=r0 offset=0 imm=32
#line 76 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_REG pc=71 dst=r7 src=r6 offset=30 imm=0
#line 77 "sample/map.c"
    if ((int64_t)r7 > (int64_t)r6)
#line 77 "sample/map.c"
        goto label_3;
    // EBPF_OP_MOV64_REG pc=72 dst=r2 src=r10 offset=0 imm=0
#line 77 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=73 dst=r2 src=r0 offset=0 imm=-4
#line 77 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=74 dst=r1 src=r0 offset=0 imm=0
#line 82 "sample/map.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=76 dst=r0 src=r0 offset=0 imm=1
#line 82 "sample/map.c"
    r0 = test_maps_helpers[1].address
#line 82 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 82 "sample/map.c"
    if ((test_maps_helpers[1].tail_call) && (r0 == 0))
#line 82 "sample/map.c"
        return 0;
    // EBPF_OP_LDDW pc=77 dst=r6 src=r0 offset=0 imm=-1
#line 82 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JEQ_IMM pc=79 dst=r0 src=r0 offset=22 imm=0
#line 83 "sample/map.c"
    if (r0 == IMMEDIATE(0))
#line 83 "sample/map.c"
        goto label_3;
    // EBPF_OP_MOV64_REG pc=80 dst=r2 src=r10 offset=0 imm=0
#line 83 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=81 dst=r2 src=r0 offset=0 imm=-4
#line 83 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=82 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=84 dst=r0 src=r0 offset=0 imm=3
#line 88 "sample/map.c"
    r0 = test_maps_helpers[2].address
#line 88 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 88 "sample/map.c"
    if ((test_maps_helpers[2].tail_call) && (r0 == 0))
#line 88 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=85 dst=r6 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=86 dst=r6 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=87 dst=r6 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_IMM pc=88 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_JSGT_REG pc=89 dst=r1 src=r6 offset=12 imm=0
#line 89 "sample/map.c"
    if ((int64_t)r1 > (int64_t)r6)
#line 89 "sample/map.c"
        goto label_3;
    // EBPF_OP_MOV64_REG pc=90 dst=r2 src=r10 offset=0 imm=0
#line 89 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=91 dst=r2 src=r0 offset=0 imm=-4
#line 89 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=92 dst=r3 src=r10 offset=0 imm=0
#line 89 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=93 dst=r3 src=r0 offset=0 imm=-8
#line 89 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=94 dst=r1 src=r0 offset=0 imm=0
#line 94 "sample/map.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_MOV64_IMM pc=96 dst=r4 src=r0 offset=0 imm=0
#line 94 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=97 dst=r0 src=r0 offset=0 imm=2
#line 94 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 94 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 94 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 94 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=98 dst=r6 src=r0 offset=0 imm=0
#line 94 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=99 dst=r6 src=r0 offset=0 imm=32
#line 94 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=100 dst=r6 src=r0 offset=0 imm=32
#line 94 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=101 dst=r6 src=r0 offset=1 imm=-1
#line 95 "sample/map.c"
    if ((int64_t)r6 > IMMEDIATE(-1))
#line 95 "sample/map.c"
        goto label_4;
label_3:
    // EBPF_OP_JA pc=102 dst=r0 src=r0 offset=-57 imm=0
#line 95 "sample/map.c"
    goto label_1;
label_4:
    // EBPF_OP_MOV64_REG pc=103 dst=r2 src=r10 offset=0 imm=0
#line 95 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=104 dst=r2 src=r0 offset=0 imm=-4
#line 95 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=105 dst=r1 src=r0 offset=0 imm=0
#line 105 "sample/map.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=107 dst=r0 src=r0 offset=0 imm=4
#line 105 "sample/map.c"
    r0 = test_maps_helpers[3].address
#line 105 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 105 "sample/map.c"
    if ((test_maps_helpers[3].tail_call) && (r0 == 0))
#line 105 "sample/map.c"
        return 0;
    // EBPF_OP_LDDW pc=108 dst=r6 src=r0 offset=0 imm=-1
#line 105 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JEQ_IMM pc=110 dst=r0 src=r0 offset=-65 imm=0
#line 296 "sample/map.c"
    if (r0 == IMMEDIATE(0))
#line 296 "sample/map.c"
        goto label_1;
    // EBPF_OP_MOV64_IMM pc=111 dst=r7 src=r0 offset=0 imm=0
#line 296 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=112 dst=r10 src=r7 offset=-4 imm=0
#line 72 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_IMM pc=113 dst=r1 src=r0 offset=0 imm=1
#line 72 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=114 dst=r10 src=r1 offset=-8 imm=0
#line 73 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=115 dst=r2 src=r10 offset=0 imm=0
#line 73 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=116 dst=r2 src=r0 offset=0 imm=-4
#line 73 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=117 dst=r3 src=r10 offset=0 imm=0
#line 73 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=118 dst=r3 src=r0 offset=0 imm=-8
#line 73 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=119 dst=r1 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r1 = POINTER(_maps[2].address);
    // EBPF_OP_MOV64_IMM pc=121 dst=r4 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=122 dst=r0 src=r0 offset=0 imm=2
#line 76 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 76 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 76 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 76 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=123 dst=r6 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=124 dst=r6 src=r0 offset=0 imm=32
#line 76 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=125 dst=r6 src=r0 offset=0 imm=32
#line 76 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_REG pc=126 dst=r7 src=r6 offset=31 imm=0
#line 77 "sample/map.c"
    if ((int64_t)r7 > (int64_t)r6)
#line 77 "sample/map.c"
        goto label_5;
    // EBPF_OP_MOV64_REG pc=127 dst=r2 src=r10 offset=0 imm=0
#line 77 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=128 dst=r2 src=r0 offset=0 imm=-4
#line 77 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=129 dst=r1 src=r0 offset=0 imm=0
#line 82 "sample/map.c"
    r1 = POINTER(_maps[2].address);
    // EBPF_OP_CALL pc=131 dst=r0 src=r0 offset=0 imm=1
#line 82 "sample/map.c"
    r0 = test_maps_helpers[1].address
#line 82 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 82 "sample/map.c"
    if ((test_maps_helpers[1].tail_call) && (r0 == 0))
#line 82 "sample/map.c"
        return 0;
    // EBPF_OP_LDDW pc=132 dst=r6 src=r0 offset=0 imm=-1
#line 82 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JEQ_IMM pc=134 dst=r0 src=r0 offset=23 imm=0
#line 83 "sample/map.c"
    if (r0 == IMMEDIATE(0))
#line 83 "sample/map.c"
        goto label_5;
    // EBPF_OP_MOV64_REG pc=135 dst=r2 src=r10 offset=0 imm=0
#line 83 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=136 dst=r2 src=r0 offset=0 imm=-4
#line 83 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=137 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r1 = POINTER(_maps[2].address);
    // EBPF_OP_CALL pc=139 dst=r0 src=r0 offset=0 imm=3
#line 88 "sample/map.c"
    r0 = test_maps_helpers[2].address
#line 88 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 88 "sample/map.c"
    if ((test_maps_helpers[2].tail_call) && (r0 == 0))
#line 88 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=140 dst=r6 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=141 dst=r6 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=142 dst=r6 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_IMM pc=143 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_JSGT_REG pc=144 dst=r1 src=r6 offset=13 imm=0
#line 89 "sample/map.c"
    if ((int64_t)r1 > (int64_t)r6)
#line 89 "sample/map.c"
        goto label_5;
    // EBPF_OP_MOV64_REG pc=145 dst=r2 src=r10 offset=0 imm=0
#line 89 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=146 dst=r2 src=r0 offset=0 imm=-4
#line 89 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=147 dst=r3 src=r10 offset=0 imm=0
#line 89 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=148 dst=r3 src=r0 offset=0 imm=-8
#line 89 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_IMM pc=149 dst=r7 src=r0 offset=0 imm=0
#line 89 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=150 dst=r1 src=r0 offset=0 imm=0
#line 94 "sample/map.c"
    r1 = POINTER(_maps[2].address);
    // EBPF_OP_MOV64_IMM pc=152 dst=r4 src=r0 offset=0 imm=0
#line 94 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=153 dst=r0 src=r0 offset=0 imm=2
#line 94 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 94 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 94 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 94 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=154 dst=r6 src=r0 offset=0 imm=0
#line 94 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=155 dst=r6 src=r0 offset=0 imm=32
#line 94 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=156 dst=r6 src=r0 offset=0 imm=32
#line 94 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=157 dst=r6 src=r0 offset=1 imm=-1
#line 95 "sample/map.c"
    if ((int64_t)r6 > IMMEDIATE(-1))
#line 95 "sample/map.c"
        goto label_6;
label_5:
    // EBPF_OP_JA pc=158 dst=r0 src=r0 offset=-113 imm=0
#line 95 "sample/map.c"
    goto label_1;
label_6:
    // EBPF_OP_STXW pc=159 dst=r10 src=r7 offset=-4 imm=0
#line 72 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_IMM pc=160 dst=r1 src=r0 offset=0 imm=1
#line 72 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=161 dst=r10 src=r1 offset=-8 imm=0
#line 73 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=162 dst=r2 src=r10 offset=0 imm=0
#line 73 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=163 dst=r2 src=r0 offset=0 imm=-4
#line 73 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=164 dst=r3 src=r10 offset=0 imm=0
#line 73 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=165 dst=r3 src=r0 offset=0 imm=-8
#line 73 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=166 dst=r1 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r1 = POINTER(_maps[3].address);
    // EBPF_OP_MOV64_IMM pc=168 dst=r4 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=169 dst=r0 src=r0 offset=0 imm=2
#line 76 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 76 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 76 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 76 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=170 dst=r6 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=171 dst=r6 src=r0 offset=0 imm=32
#line 76 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=172 dst=r6 src=r0 offset=0 imm=32
#line 76 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_REG pc=173 dst=r7 src=r6 offset=31 imm=0
#line 77 "sample/map.c"
    if ((int64_t)r7 > (int64_t)r6)
#line 77 "sample/map.c"
        goto label_7;
    // EBPF_OP_MOV64_REG pc=174 dst=r2 src=r10 offset=0 imm=0
#line 77 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=175 dst=r2 src=r0 offset=0 imm=-4
#line 77 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=176 dst=r1 src=r0 offset=0 imm=0
#line 82 "sample/map.c"
    r1 = POINTER(_maps[3].address);
    // EBPF_OP_CALL pc=178 dst=r0 src=r0 offset=0 imm=1
#line 82 "sample/map.c"
    r0 = test_maps_helpers[1].address
#line 82 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 82 "sample/map.c"
    if ((test_maps_helpers[1].tail_call) && (r0 == 0))
#line 82 "sample/map.c"
        return 0;
    // EBPF_OP_LDDW pc=179 dst=r6 src=r0 offset=0 imm=-1
#line 82 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JEQ_IMM pc=181 dst=r0 src=r0 offset=23 imm=0
#line 83 "sample/map.c"
    if (r0 == IMMEDIATE(0))
#line 83 "sample/map.c"
        goto label_7;
    // EBPF_OP_MOV64_REG pc=182 dst=r2 src=r10 offset=0 imm=0
#line 83 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=183 dst=r2 src=r0 offset=0 imm=-4
#line 83 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=184 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r1 = POINTER(_maps[3].address);
    // EBPF_OP_CALL pc=186 dst=r0 src=r0 offset=0 imm=3
#line 88 "sample/map.c"
    r0 = test_maps_helpers[2].address
#line 88 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 88 "sample/map.c"
    if ((test_maps_helpers[2].tail_call) && (r0 == 0))
#line 88 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=187 dst=r6 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=188 dst=r6 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=189 dst=r6 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_IMM pc=190 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_JSGT_REG pc=191 dst=r1 src=r6 offset=13 imm=0
#line 89 "sample/map.c"
    if ((int64_t)r1 > (int64_t)r6)
#line 89 "sample/map.c"
        goto label_7;
    // EBPF_OP_MOV64_REG pc=192 dst=r2 src=r10 offset=0 imm=0
#line 89 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=193 dst=r2 src=r0 offset=0 imm=-4
#line 89 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=194 dst=r3 src=r10 offset=0 imm=0
#line 89 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=195 dst=r3 src=r0 offset=0 imm=-8
#line 89 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_IMM pc=196 dst=r7 src=r0 offset=0 imm=0
#line 89 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=197 dst=r1 src=r0 offset=0 imm=0
#line 94 "sample/map.c"
    r1 = POINTER(_maps[3].address);
    // EBPF_OP_MOV64_IMM pc=199 dst=r4 src=r0 offset=0 imm=0
#line 94 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=200 dst=r0 src=r0 offset=0 imm=2
#line 94 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 94 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 94 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 94 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=201 dst=r6 src=r0 offset=0 imm=0
#line 94 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=202 dst=r6 src=r0 offset=0 imm=32
#line 94 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=203 dst=r6 src=r0 offset=0 imm=32
#line 94 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=204 dst=r6 src=r0 offset=1 imm=-1
#line 95 "sample/map.c"
    if ((int64_t)r6 > IMMEDIATE(-1))
#line 95 "sample/map.c"
        goto label_8;
label_7:
    // EBPF_OP_JA pc=205 dst=r0 src=r0 offset=-160 imm=0
#line 95 "sample/map.c"
    goto label_1;
label_8:
    // EBPF_OP_STXW pc=206 dst=r10 src=r7 offset=-4 imm=0
#line 72 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_IMM pc=207 dst=r1 src=r0 offset=0 imm=1
#line 72 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=208 dst=r10 src=r1 offset=-8 imm=0
#line 73 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=209 dst=r2 src=r10 offset=0 imm=0
#line 73 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=210 dst=r2 src=r0 offset=0 imm=-4
#line 73 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=211 dst=r3 src=r10 offset=0 imm=0
#line 73 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=212 dst=r3 src=r0 offset=0 imm=-8
#line 73 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=213 dst=r1 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_MOV64_IMM pc=215 dst=r4 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=216 dst=r0 src=r0 offset=0 imm=2
#line 76 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 76 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 76 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 76 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=217 dst=r6 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=218 dst=r6 src=r0 offset=0 imm=32
#line 76 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=219 dst=r6 src=r0 offset=0 imm=32
#line 76 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_REG pc=220 dst=r7 src=r6 offset=30 imm=0
#line 77 "sample/map.c"
    if ((int64_t)r7 > (int64_t)r6)
#line 77 "sample/map.c"
        goto label_9;
    // EBPF_OP_MOV64_REG pc=221 dst=r2 src=r10 offset=0 imm=0
#line 77 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=222 dst=r2 src=r0 offset=0 imm=-4
#line 77 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=223 dst=r1 src=r0 offset=0 imm=0
#line 82 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_CALL pc=225 dst=r0 src=r0 offset=0 imm=1
#line 82 "sample/map.c"
    r0 = test_maps_helpers[1].address
#line 82 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 82 "sample/map.c"
    if ((test_maps_helpers[1].tail_call) && (r0 == 0))
#line 82 "sample/map.c"
        return 0;
    // EBPF_OP_LDDW pc=226 dst=r6 src=r0 offset=0 imm=-1
#line 82 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JEQ_IMM pc=228 dst=r0 src=r0 offset=22 imm=0
#line 83 "sample/map.c"
    if (r0 == IMMEDIATE(0))
#line 83 "sample/map.c"
        goto label_9;
    // EBPF_OP_MOV64_REG pc=229 dst=r2 src=r10 offset=0 imm=0
#line 83 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=230 dst=r2 src=r0 offset=0 imm=-4
#line 83 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=231 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_CALL pc=233 dst=r0 src=r0 offset=0 imm=3
#line 88 "sample/map.c"
    r0 = test_maps_helpers[2].address
#line 88 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 88 "sample/map.c"
    if ((test_maps_helpers[2].tail_call) && (r0 == 0))
#line 88 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=234 dst=r6 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=235 dst=r6 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=236 dst=r6 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_IMM pc=237 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_JSGT_REG pc=238 dst=r1 src=r6 offset=12 imm=0
#line 89 "sample/map.c"
    if ((int64_t)r1 > (int64_t)r6)
#line 89 "sample/map.c"
        goto label_9;
    // EBPF_OP_MOV64_REG pc=239 dst=r2 src=r10 offset=0 imm=0
#line 89 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=240 dst=r2 src=r0 offset=0 imm=-4
#line 89 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=241 dst=r3 src=r10 offset=0 imm=0
#line 89 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=242 dst=r3 src=r0 offset=0 imm=-8
#line 89 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=243 dst=r1 src=r0 offset=0 imm=0
#line 94 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_MOV64_IMM pc=245 dst=r4 src=r0 offset=0 imm=0
#line 94 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=246 dst=r0 src=r0 offset=0 imm=2
#line 94 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 94 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 94 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 94 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=247 dst=r6 src=r0 offset=0 imm=0
#line 94 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=248 dst=r6 src=r0 offset=0 imm=32
#line 94 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=249 dst=r6 src=r0 offset=0 imm=32
#line 94 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=250 dst=r6 src=r0 offset=1 imm=-1
#line 95 "sample/map.c"
    if ((int64_t)r6 > IMMEDIATE(-1))
#line 95 "sample/map.c"
        goto label_10;
label_9:
    // EBPF_OP_JA pc=251 dst=r0 src=r0 offset=-206 imm=0
#line 95 "sample/map.c"
    goto label_1;
label_10:
    // EBPF_OP_MOV64_REG pc=252 dst=r2 src=r10 offset=0 imm=0
#line 95 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=253 dst=r2 src=r0 offset=0 imm=-4
#line 95 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=254 dst=r1 src=r0 offset=0 imm=0
#line 105 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_CALL pc=256 dst=r0 src=r0 offset=0 imm=4
#line 105 "sample/map.c"
    r0 = test_maps_helpers[3].address
#line 105 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 105 "sample/map.c"
    if ((test_maps_helpers[3].tail_call) && (r0 == 0))
#line 105 "sample/map.c"
        return 0;
    // EBPF_OP_LDDW pc=257 dst=r6 src=r0 offset=0 imm=-1
#line 105 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JEQ_IMM pc=259 dst=r0 src=r0 offset=-214 imm=0
#line 299 "sample/map.c"
    if (r0 == IMMEDIATE(0))
#line 299 "sample/map.c"
        goto label_1;
    // EBPF_OP_MOV64_IMM pc=260 dst=r7 src=r0 offset=0 imm=0
#line 299 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=261 dst=r10 src=r7 offset=-4 imm=0
#line 72 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_IMM pc=262 dst=r1 src=r0 offset=0 imm=1
#line 72 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=263 dst=r10 src=r1 offset=-8 imm=0
#line 73 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=264 dst=r2 src=r10 offset=0 imm=0
#line 73 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=265 dst=r2 src=r0 offset=0 imm=-4
#line 73 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=266 dst=r3 src=r10 offset=0 imm=0
#line 73 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=267 dst=r3 src=r0 offset=0 imm=-8
#line 73 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=268 dst=r1 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_MOV64_IMM pc=270 dst=r4 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=271 dst=r0 src=r0 offset=0 imm=2
#line 76 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 76 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 76 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 76 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=272 dst=r6 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=273 dst=r6 src=r0 offset=0 imm=32
#line 76 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=274 dst=r6 src=r0 offset=0 imm=32
#line 76 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_REG pc=275 dst=r7 src=r6 offset=30 imm=0
#line 77 "sample/map.c"
    if ((int64_t)r7 > (int64_t)r6)
#line 77 "sample/map.c"
        goto label_11;
    // EBPF_OP_MOV64_REG pc=276 dst=r2 src=r10 offset=0 imm=0
#line 77 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=277 dst=r2 src=r0 offset=0 imm=-4
#line 77 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=278 dst=r1 src=r0 offset=0 imm=0
#line 82 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_CALL pc=280 dst=r0 src=r0 offset=0 imm=1
#line 82 "sample/map.c"
    r0 = test_maps_helpers[1].address
#line 82 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 82 "sample/map.c"
    if ((test_maps_helpers[1].tail_call) && (r0 == 0))
#line 82 "sample/map.c"
        return 0;
    // EBPF_OP_LDDW pc=281 dst=r6 src=r0 offset=0 imm=-1
#line 82 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JEQ_IMM pc=283 dst=r0 src=r0 offset=22 imm=0
#line 83 "sample/map.c"
    if (r0 == IMMEDIATE(0))
#line 83 "sample/map.c"
        goto label_11;
    // EBPF_OP_MOV64_REG pc=284 dst=r2 src=r10 offset=0 imm=0
#line 83 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=285 dst=r2 src=r0 offset=0 imm=-4
#line 83 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=286 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_CALL pc=288 dst=r0 src=r0 offset=0 imm=3
#line 88 "sample/map.c"
    r0 = test_maps_helpers[2].address
#line 88 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 88 "sample/map.c"
    if ((test_maps_helpers[2].tail_call) && (r0 == 0))
#line 88 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=289 dst=r6 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=290 dst=r6 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=291 dst=r6 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_IMM pc=292 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_JSGT_REG pc=293 dst=r1 src=r6 offset=12 imm=0
#line 89 "sample/map.c"
    if ((int64_t)r1 > (int64_t)r6)
#line 89 "sample/map.c"
        goto label_11;
    // EBPF_OP_MOV64_REG pc=294 dst=r2 src=r10 offset=0 imm=0
#line 89 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=295 dst=r2 src=r0 offset=0 imm=-4
#line 89 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=296 dst=r3 src=r10 offset=0 imm=0
#line 89 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=297 dst=r3 src=r0 offset=0 imm=-8
#line 89 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=298 dst=r1 src=r0 offset=0 imm=0
#line 94 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_MOV64_IMM pc=300 dst=r4 src=r0 offset=0 imm=0
#line 94 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=301 dst=r0 src=r0 offset=0 imm=2
#line 94 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 94 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 94 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 94 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=302 dst=r6 src=r0 offset=0 imm=0
#line 94 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=303 dst=r6 src=r0 offset=0 imm=32
#line 94 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=304 dst=r6 src=r0 offset=0 imm=32
#line 94 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=305 dst=r6 src=r0 offset=1 imm=-1
#line 95 "sample/map.c"
    if ((int64_t)r6 > IMMEDIATE(-1))
#line 95 "sample/map.c"
        goto label_12;
label_11:
    // EBPF_OP_JA pc=306 dst=r0 src=r0 offset=-261 imm=0
#line 95 "sample/map.c"
    goto label_1;
label_12:
    // EBPF_OP_MOV64_REG pc=307 dst=r2 src=r10 offset=0 imm=0
#line 95 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=308 dst=r2 src=r0 offset=0 imm=-4
#line 95 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=309 dst=r1 src=r0 offset=0 imm=0
#line 105 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_CALL pc=311 dst=r0 src=r0 offset=0 imm=4
#line 105 "sample/map.c"
    r0 = test_maps_helpers[3].address
#line 105 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 105 "sample/map.c"
    if ((test_maps_helpers[3].tail_call) && (r0 == 0))
#line 105 "sample/map.c"
        return 0;
    // EBPF_OP_LDDW pc=312 dst=r6 src=r0 offset=0 imm=-1
#line 105 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JEQ_IMM pc=314 dst=r0 src=r0 offset=-269 imm=0
#line 300 "sample/map.c"
    if (r0 == IMMEDIATE(0))
#line 300 "sample/map.c"
        goto label_1;
    // EBPF_OP_MOV64_IMM pc=315 dst=r7 src=r0 offset=0 imm=0
#line 300 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=316 dst=r10 src=r7 offset=-4 imm=0
#line 116 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_IMM pc=317 dst=r8 src=r0 offset=0 imm=1
#line 116 "sample/map.c"
    r8 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=318 dst=r10 src=r8 offset=-8 imm=0
#line 117 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r8;
    // EBPF_OP_MOV64_REG pc=319 dst=r2 src=r10 offset=0 imm=0
#line 117 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=320 dst=r2 src=r0 offset=0 imm=-4
#line 117 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=321 dst=r3 src=r10 offset=0 imm=0
#line 117 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=322 dst=r3 src=r0 offset=0 imm=-8
#line 117 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=323 dst=r1 src=r0 offset=0 imm=0
#line 131 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_MOV64_IMM pc=325 dst=r4 src=r0 offset=0 imm=0
#line 131 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=326 dst=r0 src=r0 offset=0 imm=2
#line 131 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 131 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 131 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 131 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=327 dst=r6 src=r0 offset=0 imm=0
#line 131 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=328 dst=r6 src=r0 offset=0 imm=32
#line 131 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=329 dst=r6 src=r0 offset=0 imm=32
#line 131 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_REG pc=330 dst=r7 src=r6 offset=144 imm=0
#line 132 "sample/map.c"
    if ((int64_t)r7 > (int64_t)r6)
#line 132 "sample/map.c"
        goto label_13;
    // EBPF_OP_STXW pc=331 dst=r10 src=r8 offset=-4 imm=0
#line 136 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r8;
    // EBPF_OP_MOV64_REG pc=332 dst=r2 src=r10 offset=0 imm=0
#line 136 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=333 dst=r2 src=r0 offset=0 imm=-4
#line 136 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=334 dst=r3 src=r10 offset=0 imm=0
#line 136 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=335 dst=r3 src=r0 offset=0 imm=-8
#line 136 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=336 dst=r1 src=r0 offset=0 imm=0
#line 137 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_MOV64_IMM pc=338 dst=r4 src=r0 offset=0 imm=0
#line 137 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=339 dst=r0 src=r0 offset=0 imm=2
#line 137 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 137 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 137 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 137 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=340 dst=r6 src=r0 offset=0 imm=0
#line 137 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=341 dst=r6 src=r0 offset=0 imm=32
#line 137 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=342 dst=r6 src=r0 offset=0 imm=32
#line 137 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_REG pc=343 dst=r7 src=r6 offset=131 imm=0
#line 138 "sample/map.c"
    if ((int64_t)r7 > (int64_t)r6)
#line 138 "sample/map.c"
        goto label_13;
    // EBPF_OP_MOV64_IMM pc=344 dst=r1 src=r0 offset=0 imm=2
#line 138 "sample/map.c"
    r1 = IMMEDIATE(2);
    // EBPF_OP_STXW pc=345 dst=r10 src=r1 offset=-4 imm=0
#line 142 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=346 dst=r2 src=r10 offset=0 imm=0
#line 142 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=347 dst=r2 src=r0 offset=0 imm=-4
#line 142 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=348 dst=r3 src=r10 offset=0 imm=0
#line 142 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=349 dst=r3 src=r0 offset=0 imm=-8
#line 142 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_IMM pc=350 dst=r7 src=r0 offset=0 imm=0
#line 142 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=351 dst=r1 src=r0 offset=0 imm=0
#line 143 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_MOV64_IMM pc=353 dst=r4 src=r0 offset=0 imm=0
#line 143 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=354 dst=r0 src=r0 offset=0 imm=2
#line 143 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 143 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 143 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 143 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=355 dst=r6 src=r0 offset=0 imm=0
#line 143 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=356 dst=r6 src=r0 offset=0 imm=32
#line 143 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=357 dst=r6 src=r0 offset=0 imm=32
#line 143 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_REG pc=358 dst=r7 src=r6 offset=116 imm=0
#line 144 "sample/map.c"
    if ((int64_t)r7 > (int64_t)r6)
#line 144 "sample/map.c"
        goto label_13;
    // EBPF_OP_MOV64_IMM pc=359 dst=r1 src=r0 offset=0 imm=3
#line 144 "sample/map.c"
    r1 = IMMEDIATE(3);
    // EBPF_OP_STXW pc=360 dst=r10 src=r1 offset=-4 imm=0
#line 148 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=361 dst=r2 src=r10 offset=0 imm=0
#line 148 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=362 dst=r2 src=r0 offset=0 imm=-4
#line 148 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=363 dst=r3 src=r10 offset=0 imm=0
#line 148 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=364 dst=r3 src=r0 offset=0 imm=-8
#line 148 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=365 dst=r1 src=r0 offset=0 imm=0
#line 149 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_MOV64_IMM pc=367 dst=r4 src=r0 offset=0 imm=0
#line 149 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=368 dst=r0 src=r0 offset=0 imm=2
#line 149 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 149 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 149 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 149 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=369 dst=r6 src=r0 offset=0 imm=0
#line 149 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=370 dst=r6 src=r0 offset=0 imm=32
#line 149 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=371 dst=r6 src=r0 offset=0 imm=32
#line 149 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_REG pc=372 dst=r7 src=r6 offset=102 imm=0
#line 150 "sample/map.c"
    if ((int64_t)r7 > (int64_t)r6)
#line 150 "sample/map.c"
        goto label_13;
    // EBPF_OP_MOV64_IMM pc=373 dst=r1 src=r0 offset=0 imm=4
#line 150 "sample/map.c"
    r1 = IMMEDIATE(4);
    // EBPF_OP_STXW pc=374 dst=r10 src=r1 offset=-4 imm=0
#line 154 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=375 dst=r2 src=r10 offset=0 imm=0
#line 154 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=376 dst=r2 src=r0 offset=0 imm=-4
#line 154 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=377 dst=r3 src=r10 offset=0 imm=0
#line 154 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=378 dst=r3 src=r0 offset=0 imm=-8
#line 154 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_IMM pc=379 dst=r7 src=r0 offset=0 imm=0
#line 154 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=380 dst=r1 src=r0 offset=0 imm=0
#line 155 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_MOV64_IMM pc=382 dst=r4 src=r0 offset=0 imm=0
#line 155 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=383 dst=r0 src=r0 offset=0 imm=2
#line 155 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 155 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 155 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 155 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=384 dst=r6 src=r0 offset=0 imm=0
#line 155 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=385 dst=r6 src=r0 offset=0 imm=32
#line 155 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=386 dst=r6 src=r0 offset=0 imm=32
#line 155 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_REG pc=387 dst=r7 src=r6 offset=87 imm=0
#line 156 "sample/map.c"
    if ((int64_t)r7 > (int64_t)r6)
#line 156 "sample/map.c"
        goto label_13;
    // EBPF_OP_MOV64_IMM pc=388 dst=r1 src=r0 offset=0 imm=5
#line 156 "sample/map.c"
    r1 = IMMEDIATE(5);
    // EBPF_OP_STXW pc=389 dst=r10 src=r1 offset=-4 imm=0
#line 160 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=390 dst=r2 src=r10 offset=0 imm=0
#line 160 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=391 dst=r2 src=r0 offset=0 imm=-4
#line 160 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=392 dst=r3 src=r10 offset=0 imm=0
#line 160 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=393 dst=r3 src=r0 offset=0 imm=-8
#line 160 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=394 dst=r1 src=r0 offset=0 imm=0
#line 161 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_MOV64_IMM pc=396 dst=r4 src=r0 offset=0 imm=0
#line 161 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=397 dst=r0 src=r0 offset=0 imm=2
#line 161 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 161 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 161 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 161 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=398 dst=r6 src=r0 offset=0 imm=0
#line 161 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=399 dst=r6 src=r0 offset=0 imm=32
#line 161 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=400 dst=r6 src=r0 offset=0 imm=32
#line 161 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_REG pc=401 dst=r7 src=r6 offset=73 imm=0
#line 162 "sample/map.c"
    if ((int64_t)r7 > (int64_t)r6)
#line 162 "sample/map.c"
        goto label_13;
    // EBPF_OP_MOV64_IMM pc=402 dst=r1 src=r0 offset=0 imm=6
#line 162 "sample/map.c"
    r1 = IMMEDIATE(6);
    // EBPF_OP_STXW pc=403 dst=r10 src=r1 offset=-4 imm=0
#line 166 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=404 dst=r2 src=r10 offset=0 imm=0
#line 166 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=405 dst=r2 src=r0 offset=0 imm=-4
#line 166 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=406 dst=r3 src=r10 offset=0 imm=0
#line 166 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=407 dst=r3 src=r0 offset=0 imm=-8
#line 166 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_IMM pc=408 dst=r7 src=r0 offset=0 imm=0
#line 166 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=409 dst=r1 src=r0 offset=0 imm=0
#line 167 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_MOV64_IMM pc=411 dst=r4 src=r0 offset=0 imm=0
#line 167 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=412 dst=r0 src=r0 offset=0 imm=2
#line 167 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 167 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 167 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 167 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=413 dst=r6 src=r0 offset=0 imm=0
#line 167 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=414 dst=r6 src=r0 offset=0 imm=32
#line 167 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=415 dst=r6 src=r0 offset=0 imm=32
#line 167 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_REG pc=416 dst=r7 src=r6 offset=58 imm=0
#line 168 "sample/map.c"
    if ((int64_t)r7 > (int64_t)r6)
#line 168 "sample/map.c"
        goto label_13;
    // EBPF_OP_MOV64_IMM pc=417 dst=r1 src=r0 offset=0 imm=7
#line 168 "sample/map.c"
    r1 = IMMEDIATE(7);
    // EBPF_OP_STXW pc=418 dst=r10 src=r1 offset=-4 imm=0
#line 172 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=419 dst=r2 src=r10 offset=0 imm=0
#line 172 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=420 dst=r2 src=r0 offset=0 imm=-4
#line 172 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=421 dst=r3 src=r10 offset=0 imm=0
#line 172 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=422 dst=r3 src=r0 offset=0 imm=-8
#line 172 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=423 dst=r1 src=r0 offset=0 imm=0
#line 173 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_MOV64_IMM pc=425 dst=r4 src=r0 offset=0 imm=0
#line 173 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=426 dst=r0 src=r0 offset=0 imm=2
#line 173 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 173 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 173 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 173 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=427 dst=r6 src=r0 offset=0 imm=0
#line 173 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=428 dst=r6 src=r0 offset=0 imm=32
#line 173 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=429 dst=r6 src=r0 offset=0 imm=32
#line 173 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_REG pc=430 dst=r7 src=r6 offset=44 imm=0
#line 174 "sample/map.c"
    if ((int64_t)r7 > (int64_t)r6)
#line 174 "sample/map.c"
        goto label_13;
    // EBPF_OP_MOV64_IMM pc=431 dst=r1 src=r0 offset=0 imm=8
#line 174 "sample/map.c"
    r1 = IMMEDIATE(8);
    // EBPF_OP_STXW pc=432 dst=r10 src=r1 offset=-4 imm=0
#line 178 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=433 dst=r2 src=r10 offset=0 imm=0
#line 178 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=434 dst=r2 src=r0 offset=0 imm=-4
#line 178 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=435 dst=r3 src=r10 offset=0 imm=0
#line 178 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=436 dst=r3 src=r0 offset=0 imm=-8
#line 178 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_IMM pc=437 dst=r7 src=r0 offset=0 imm=0
#line 178 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=438 dst=r1 src=r0 offset=0 imm=0
#line 179 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_MOV64_IMM pc=440 dst=r4 src=r0 offset=0 imm=0
#line 179 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=441 dst=r0 src=r0 offset=0 imm=2
#line 179 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 179 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 179 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 179 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=442 dst=r6 src=r0 offset=0 imm=0
#line 179 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=443 dst=r6 src=r0 offset=0 imm=32
#line 179 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=444 dst=r6 src=r0 offset=0 imm=32
#line 179 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_REG pc=445 dst=r7 src=r6 offset=29 imm=0
#line 180 "sample/map.c"
    if ((int64_t)r7 > (int64_t)r6)
#line 180 "sample/map.c"
        goto label_13;
    // EBPF_OP_MOV64_IMM pc=446 dst=r1 src=r0 offset=0 imm=9
#line 180 "sample/map.c"
    r1 = IMMEDIATE(9);
    // EBPF_OP_STXW pc=447 dst=r10 src=r1 offset=-4 imm=0
#line 184 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=448 dst=r2 src=r10 offset=0 imm=0
#line 184 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=449 dst=r2 src=r0 offset=0 imm=-4
#line 184 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=450 dst=r3 src=r10 offset=0 imm=0
#line 184 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=451 dst=r3 src=r0 offset=0 imm=-8
#line 184 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=452 dst=r1 src=r0 offset=0 imm=0
#line 185 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_MOV64_IMM pc=454 dst=r4 src=r0 offset=0 imm=0
#line 185 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=455 dst=r0 src=r0 offset=0 imm=2
#line 185 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 185 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 185 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 185 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=456 dst=r6 src=r0 offset=0 imm=0
#line 185 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=457 dst=r6 src=r0 offset=0 imm=32
#line 185 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=458 dst=r6 src=r0 offset=0 imm=32
#line 185 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_REG pc=459 dst=r7 src=r6 offset=15 imm=0
#line 186 "sample/map.c"
    if ((int64_t)r7 > (int64_t)r6)
#line 186 "sample/map.c"
        goto label_13;
    // EBPF_OP_MOV64_IMM pc=460 dst=r1 src=r0 offset=0 imm=10
#line 186 "sample/map.c"
    r1 = IMMEDIATE(10);
    // EBPF_OP_STXW pc=461 dst=r10 src=r1 offset=-4 imm=0
#line 190 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=462 dst=r2 src=r10 offset=0 imm=0
#line 190 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=463 dst=r2 src=r0 offset=0 imm=-4
#line 190 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=464 dst=r3 src=r10 offset=0 imm=0
#line 190 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=465 dst=r3 src=r0 offset=0 imm=-8
#line 190 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_IMM pc=466 dst=r7 src=r0 offset=0 imm=0
#line 190 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=467 dst=r1 src=r0 offset=0 imm=0
#line 191 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_MOV64_IMM pc=469 dst=r4 src=r0 offset=0 imm=0
#line 191 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=470 dst=r0 src=r0 offset=0 imm=2
#line 191 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 191 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 191 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 191 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=471 dst=r6 src=r0 offset=0 imm=0
#line 191 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=472 dst=r6 src=r0 offset=0 imm=32
#line 191 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=473 dst=r6 src=r0 offset=0 imm=32
#line 191 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=474 dst=r6 src=r0 offset=1 imm=-1
#line 191 "sample/map.c"
    if ((int64_t)r6 > IMMEDIATE(-1))
#line 191 "sample/map.c"
        goto label_14;
label_13:
    // EBPF_OP_JA pc=475 dst=r0 src=r0 offset=-430 imm=0
#line 191 "sample/map.c"
    goto label_1;
label_14:
    // EBPF_OP_STXW pc=476 dst=r10 src=r7 offset=-4 imm=0
#line 116 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_IMM pc=477 dst=r8 src=r0 offset=0 imm=1
#line 116 "sample/map.c"
    r8 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=478 dst=r10 src=r8 offset=-8 imm=0
#line 117 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r8;
    // EBPF_OP_MOV64_REG pc=479 dst=r2 src=r10 offset=0 imm=0
#line 117 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=480 dst=r2 src=r0 offset=0 imm=-4
#line 117 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=481 dst=r3 src=r10 offset=0 imm=0
#line 117 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=482 dst=r3 src=r0 offset=0 imm=-8
#line 117 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=483 dst=r1 src=r0 offset=0 imm=0
#line 131 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_MOV64_IMM pc=485 dst=r4 src=r0 offset=0 imm=0
#line 131 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=486 dst=r0 src=r0 offset=0 imm=2
#line 131 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 131 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 131 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 131 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=487 dst=r6 src=r0 offset=0 imm=0
#line 131 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=488 dst=r6 src=r0 offset=0 imm=32
#line 131 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=489 dst=r6 src=r0 offset=0 imm=32
#line 131 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_REG pc=490 dst=r7 src=r6 offset=145 imm=0
#line 132 "sample/map.c"
    if ((int64_t)r7 > (int64_t)r6)
#line 132 "sample/map.c"
        goto label_15;
    // EBPF_OP_STXW pc=491 dst=r10 src=r8 offset=-4 imm=0
#line 136 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r8;
    // EBPF_OP_MOV64_REG pc=492 dst=r2 src=r10 offset=0 imm=0
#line 136 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=493 dst=r2 src=r0 offset=0 imm=-4
#line 136 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=494 dst=r3 src=r10 offset=0 imm=0
#line 136 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=495 dst=r3 src=r0 offset=0 imm=-8
#line 136 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_IMM pc=496 dst=r7 src=r0 offset=0 imm=0
#line 136 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=497 dst=r1 src=r0 offset=0 imm=0
#line 137 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_MOV64_IMM pc=499 dst=r4 src=r0 offset=0 imm=0
#line 137 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=500 dst=r0 src=r0 offset=0 imm=2
#line 137 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 137 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 137 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 137 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=501 dst=r6 src=r0 offset=0 imm=0
#line 137 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=502 dst=r6 src=r0 offset=0 imm=32
#line 137 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=503 dst=r6 src=r0 offset=0 imm=32
#line 137 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_REG pc=504 dst=r7 src=r6 offset=131 imm=0
#line 138 "sample/map.c"
    if ((int64_t)r7 > (int64_t)r6)
#line 138 "sample/map.c"
        goto label_15;
    // EBPF_OP_MOV64_IMM pc=505 dst=r1 src=r0 offset=0 imm=2
#line 138 "sample/map.c"
    r1 = IMMEDIATE(2);
    // EBPF_OP_STXW pc=506 dst=r10 src=r1 offset=-4 imm=0
#line 142 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=507 dst=r2 src=r10 offset=0 imm=0
#line 142 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=508 dst=r2 src=r0 offset=0 imm=-4
#line 142 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=509 dst=r3 src=r10 offset=0 imm=0
#line 142 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=510 dst=r3 src=r0 offset=0 imm=-8
#line 142 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=511 dst=r1 src=r0 offset=0 imm=0
#line 143 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_MOV64_IMM pc=513 dst=r4 src=r0 offset=0 imm=0
#line 143 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=514 dst=r0 src=r0 offset=0 imm=2
#line 143 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 143 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 143 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 143 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=515 dst=r6 src=r0 offset=0 imm=0
#line 143 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=516 dst=r6 src=r0 offset=0 imm=32
#line 143 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=517 dst=r6 src=r0 offset=0 imm=32
#line 143 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_REG pc=518 dst=r7 src=r6 offset=117 imm=0
#line 144 "sample/map.c"
    if ((int64_t)r7 > (int64_t)r6)
#line 144 "sample/map.c"
        goto label_15;
    // EBPF_OP_MOV64_IMM pc=519 dst=r1 src=r0 offset=0 imm=3
#line 144 "sample/map.c"
    r1 = IMMEDIATE(3);
    // EBPF_OP_STXW pc=520 dst=r10 src=r1 offset=-4 imm=0
#line 148 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=521 dst=r2 src=r10 offset=0 imm=0
#line 148 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=522 dst=r2 src=r0 offset=0 imm=-4
#line 148 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=523 dst=r3 src=r10 offset=0 imm=0
#line 148 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=524 dst=r3 src=r0 offset=0 imm=-8
#line 148 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_IMM pc=525 dst=r7 src=r0 offset=0 imm=0
#line 148 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=526 dst=r1 src=r0 offset=0 imm=0
#line 149 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_MOV64_IMM pc=528 dst=r4 src=r0 offset=0 imm=0
#line 149 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=529 dst=r0 src=r0 offset=0 imm=2
#line 149 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 149 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 149 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 149 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=530 dst=r6 src=r0 offset=0 imm=0
#line 149 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=531 dst=r6 src=r0 offset=0 imm=32
#line 149 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=532 dst=r6 src=r0 offset=0 imm=32
#line 149 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_REG pc=533 dst=r7 src=r6 offset=102 imm=0
#line 150 "sample/map.c"
    if ((int64_t)r7 > (int64_t)r6)
#line 150 "sample/map.c"
        goto label_15;
    // EBPF_OP_MOV64_IMM pc=534 dst=r1 src=r0 offset=0 imm=4
#line 150 "sample/map.c"
    r1 = IMMEDIATE(4);
    // EBPF_OP_STXW pc=535 dst=r10 src=r1 offset=-4 imm=0
#line 154 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=536 dst=r2 src=r10 offset=0 imm=0
#line 154 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=537 dst=r2 src=r0 offset=0 imm=-4
#line 154 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=538 dst=r3 src=r10 offset=0 imm=0
#line 154 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=539 dst=r3 src=r0 offset=0 imm=-8
#line 154 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=540 dst=r1 src=r0 offset=0 imm=0
#line 155 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_MOV64_IMM pc=542 dst=r4 src=r0 offset=0 imm=0
#line 155 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=543 dst=r0 src=r0 offset=0 imm=2
#line 155 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 155 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 155 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 155 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=544 dst=r6 src=r0 offset=0 imm=0
#line 155 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=545 dst=r6 src=r0 offset=0 imm=32
#line 155 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=546 dst=r6 src=r0 offset=0 imm=32
#line 155 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_REG pc=547 dst=r7 src=r6 offset=88 imm=0
#line 156 "sample/map.c"
    if ((int64_t)r7 > (int64_t)r6)
#line 156 "sample/map.c"
        goto label_15;
    // EBPF_OP_MOV64_IMM pc=548 dst=r1 src=r0 offset=0 imm=5
#line 156 "sample/map.c"
    r1 = IMMEDIATE(5);
    // EBPF_OP_STXW pc=549 dst=r10 src=r1 offset=-4 imm=0
#line 160 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=550 dst=r2 src=r10 offset=0 imm=0
#line 160 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=551 dst=r2 src=r0 offset=0 imm=-4
#line 160 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=552 dst=r3 src=r10 offset=0 imm=0
#line 160 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=553 dst=r3 src=r0 offset=0 imm=-8
#line 160 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_IMM pc=554 dst=r7 src=r0 offset=0 imm=0
#line 160 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=555 dst=r1 src=r0 offset=0 imm=0
#line 161 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_MOV64_IMM pc=557 dst=r4 src=r0 offset=0 imm=0
#line 161 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=558 dst=r0 src=r0 offset=0 imm=2
#line 161 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 161 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 161 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 161 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=559 dst=r6 src=r0 offset=0 imm=0
#line 161 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=560 dst=r6 src=r0 offset=0 imm=32
#line 161 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=561 dst=r6 src=r0 offset=0 imm=32
#line 161 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_REG pc=562 dst=r7 src=r6 offset=73 imm=0
#line 162 "sample/map.c"
    if ((int64_t)r7 > (int64_t)r6)
#line 162 "sample/map.c"
        goto label_15;
    // EBPF_OP_MOV64_IMM pc=563 dst=r1 src=r0 offset=0 imm=6
#line 162 "sample/map.c"
    r1 = IMMEDIATE(6);
    // EBPF_OP_STXW pc=564 dst=r10 src=r1 offset=-4 imm=0
#line 166 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=565 dst=r2 src=r10 offset=0 imm=0
#line 166 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=566 dst=r2 src=r0 offset=0 imm=-4
#line 166 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=567 dst=r3 src=r10 offset=0 imm=0
#line 166 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=568 dst=r3 src=r0 offset=0 imm=-8
#line 166 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=569 dst=r1 src=r0 offset=0 imm=0
#line 167 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_MOV64_IMM pc=571 dst=r4 src=r0 offset=0 imm=0
#line 167 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=572 dst=r0 src=r0 offset=0 imm=2
#line 167 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 167 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 167 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 167 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=573 dst=r6 src=r0 offset=0 imm=0
#line 167 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=574 dst=r6 src=r0 offset=0 imm=32
#line 167 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=575 dst=r6 src=r0 offset=0 imm=32
#line 167 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_REG pc=576 dst=r7 src=r6 offset=59 imm=0
#line 168 "sample/map.c"
    if ((int64_t)r7 > (int64_t)r6)
#line 168 "sample/map.c"
        goto label_15;
    // EBPF_OP_MOV64_IMM pc=577 dst=r1 src=r0 offset=0 imm=7
#line 168 "sample/map.c"
    r1 = IMMEDIATE(7);
    // EBPF_OP_STXW pc=578 dst=r10 src=r1 offset=-4 imm=0
#line 172 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=579 dst=r2 src=r10 offset=0 imm=0
#line 172 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=580 dst=r2 src=r0 offset=0 imm=-4
#line 172 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=581 dst=r3 src=r10 offset=0 imm=0
#line 172 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=582 dst=r3 src=r0 offset=0 imm=-8
#line 172 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_IMM pc=583 dst=r7 src=r0 offset=0 imm=0
#line 172 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=584 dst=r1 src=r0 offset=0 imm=0
#line 173 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_MOV64_IMM pc=586 dst=r4 src=r0 offset=0 imm=0
#line 173 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=587 dst=r0 src=r0 offset=0 imm=2
#line 173 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 173 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 173 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 173 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=588 dst=r6 src=r0 offset=0 imm=0
#line 173 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=589 dst=r6 src=r0 offset=0 imm=32
#line 173 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=590 dst=r6 src=r0 offset=0 imm=32
#line 173 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_REG pc=591 dst=r7 src=r6 offset=44 imm=0
#line 174 "sample/map.c"
    if ((int64_t)r7 > (int64_t)r6)
#line 174 "sample/map.c"
        goto label_15;
    // EBPF_OP_MOV64_IMM pc=592 dst=r1 src=r0 offset=0 imm=8
#line 174 "sample/map.c"
    r1 = IMMEDIATE(8);
    // EBPF_OP_STXW pc=593 dst=r10 src=r1 offset=-4 imm=0
#line 178 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=594 dst=r2 src=r10 offset=0 imm=0
#line 178 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=595 dst=r2 src=r0 offset=0 imm=-4
#line 178 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=596 dst=r3 src=r10 offset=0 imm=0
#line 178 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=597 dst=r3 src=r0 offset=0 imm=-8
#line 178 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=598 dst=r1 src=r0 offset=0 imm=0
#line 179 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_MOV64_IMM pc=600 dst=r4 src=r0 offset=0 imm=0
#line 179 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=601 dst=r0 src=r0 offset=0 imm=2
#line 179 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 179 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 179 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 179 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=602 dst=r6 src=r0 offset=0 imm=0
#line 179 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=603 dst=r6 src=r0 offset=0 imm=32
#line 179 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=604 dst=r6 src=r0 offset=0 imm=32
#line 179 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_REG pc=605 dst=r7 src=r6 offset=30 imm=0
#line 180 "sample/map.c"
    if ((int64_t)r7 > (int64_t)r6)
#line 180 "sample/map.c"
        goto label_15;
    // EBPF_OP_MOV64_IMM pc=606 dst=r1 src=r0 offset=0 imm=9
#line 180 "sample/map.c"
    r1 = IMMEDIATE(9);
    // EBPF_OP_STXW pc=607 dst=r10 src=r1 offset=-4 imm=0
#line 184 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=608 dst=r2 src=r10 offset=0 imm=0
#line 184 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=609 dst=r2 src=r0 offset=0 imm=-4
#line 184 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=610 dst=r3 src=r10 offset=0 imm=0
#line 184 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=611 dst=r3 src=r0 offset=0 imm=-8
#line 184 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_IMM pc=612 dst=r7 src=r0 offset=0 imm=0
#line 184 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=613 dst=r1 src=r0 offset=0 imm=0
#line 185 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_MOV64_IMM pc=615 dst=r4 src=r0 offset=0 imm=0
#line 185 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=616 dst=r0 src=r0 offset=0 imm=2
#line 185 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 185 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 185 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 185 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=617 dst=r6 src=r0 offset=0 imm=0
#line 185 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=618 dst=r6 src=r0 offset=0 imm=32
#line 185 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=619 dst=r6 src=r0 offset=0 imm=32
#line 185 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_REG pc=620 dst=r7 src=r6 offset=15 imm=0
#line 186 "sample/map.c"
    if ((int64_t)r7 > (int64_t)r6)
#line 186 "sample/map.c"
        goto label_15;
    // EBPF_OP_MOV64_IMM pc=621 dst=r1 src=r0 offset=0 imm=10
#line 186 "sample/map.c"
    r1 = IMMEDIATE(10);
    // EBPF_OP_STXW pc=622 dst=r10 src=r1 offset=-4 imm=0
#line 190 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=623 dst=r2 src=r10 offset=0 imm=0
#line 190 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=624 dst=r2 src=r0 offset=0 imm=-4
#line 190 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=625 dst=r3 src=r10 offset=0 imm=0
#line 190 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=626 dst=r3 src=r0 offset=0 imm=-8
#line 190 "sample/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_IMM pc=627 dst=r7 src=r0 offset=0 imm=0
#line 190 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=628 dst=r1 src=r0 offset=0 imm=0
#line 191 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_MOV64_IMM pc=630 dst=r4 src=r0 offset=0 imm=0
#line 191 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=631 dst=r0 src=r0 offset=0 imm=2
#line 191 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 191 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 191 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 191 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=632 dst=r6 src=r0 offset=0 imm=0
#line 191 "sample/map.c"
    r6 = r0;
    // EBPF_OP_LSH64_IMM pc=633 dst=r6 src=r0 offset=0 imm=32
#line 191 "sample/map.c"
    r6 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=634 dst=r6 src=r0 offset=0 imm=32
#line 191 "sample/map.c"
    r6 = (int64_t)r6 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=635 dst=r6 src=r0 offset=1 imm=-1
#line 191 "sample/map.c"
    if ((int64_t)r6 > IMMEDIATE(-1))
#line 191 "sample/map.c"
        goto label_16;
label_15:
    // EBPF_OP_JA pc=636 dst=r0 src=r0 offset=-591 imm=0
#line 191 "sample/map.c"
    goto label_1;
label_16:
    // EBPF_OP_STXW pc=637 dst=r10 src=r7 offset=-4 imm=0
#line 242 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=638 dst=r2 src=r10 offset=0 imm=0
#line 242 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=639 dst=r2 src=r0 offset=0 imm=-4
#line 242 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=640 dst=r1 src=r0 offset=0 imm=0
#line 242 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=642 dst=r0 src=r0 offset=0 imm=18
#line 242 "sample/map.c"
    r0 = test_maps_helpers[4].address
#line 242 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 242 "sample/map.c"
    if ((test_maps_helpers[4].tail_call) && (r0 == 0))
#line 242 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=643 dst=r1 src=r0 offset=0 imm=0
#line 242 "sample/map.c"
    r1 = r0;
    // EBPF_OP_LSH64_IMM pc=644 dst=r1 src=r0 offset=0 imm=32
#line 242 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=645 dst=r1 src=r0 offset=0 imm=32
#line 242 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_MOV64_IMM pc=646 dst=r6 src=r0 offset=0 imm=-1
#line 242 "sample/map.c"
    r6 = IMMEDIATE(-1);
    // EBPF_OP_LDDW pc=647 dst=r2 src=r0 offset=0 imm=-7
#line 242 "sample/map.c"
    r2 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=649 dst=r1 src=r2 offset=1 imm=0
#line 242 "sample/map.c"
    if (r1 == r2)
#line 242 "sample/map.c"
        goto label_17;
    // EBPF_OP_MOV64_REG pc=650 dst=r6 src=r0 offset=0 imm=0
#line 242 "sample/map.c"
    r6 = r0;
label_17:
    // EBPF_OP_JNE_REG pc=651 dst=r1 src=r2 offset=409 imm=0
#line 242 "sample/map.c"
    if (r1 != r2)
#line 242 "sample/map.c"
        goto label_36;
    // EBPF_OP_LDXW pc=652 dst=r1 src=r10 offset=-4 imm=0
#line 242 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=653 dst=r1 src=r0 offset=407 imm=0
#line 242 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 242 "sample/map.c"
        goto label_36;
    // EBPF_OP_MOV64_IMM pc=654 dst=r1 src=r0 offset=0 imm=0
#line 242 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=655 dst=r10 src=r1 offset=-4 imm=0
#line 243 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=656 dst=r2 src=r10 offset=0 imm=0
#line 243 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=657 dst=r2 src=r0 offset=0 imm=-4
#line 243 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=658 dst=r1 src=r0 offset=0 imm=0
#line 243 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=660 dst=r0 src=r0 offset=0 imm=17
#line 243 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 243 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 243 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 243 "sample/map.c"
        return 0;
    // EBPF_OP_LDXW pc=661 dst=r1 src=r10 offset=-4 imm=0
#line 243 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=662 dst=r7 src=r6 offset=0 imm=0
#line 243 "sample/map.c"
    r7 = r6;
    // EBPF_OP_JEQ_IMM pc=663 dst=r1 src=r0 offset=1 imm=0
#line 243 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 243 "sample/map.c"
        goto label_18;
    // EBPF_OP_MOV64_IMM pc=664 dst=r7 src=r0 offset=0 imm=-1
#line 243 "sample/map.c"
    r7 = IMMEDIATE(-1);
label_18:
    // EBPF_OP_MOV64_REG pc=665 dst=r2 src=r0 offset=0 imm=0
#line 243 "sample/map.c"
    r2 = r0;
    // EBPF_OP_LSH64_IMM pc=666 dst=r2 src=r0 offset=0 imm=32
#line 243 "sample/map.c"
    r2 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=667 dst=r2 src=r0 offset=0 imm=32
#line 243 "sample/map.c"
    r2 >>= IMMEDIATE(32);
    // EBPF_OP_LDDW pc=668 dst=r3 src=r0 offset=0 imm=-7
#line 243 "sample/map.c"
    r3 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=670 dst=r2 src=r3 offset=1 imm=0
#line 243 "sample/map.c"
    if (r2 == r3)
#line 243 "sample/map.c"
        goto label_19;
    // EBPF_OP_MOV64_REG pc=671 dst=r7 src=r0 offset=0 imm=0
#line 243 "sample/map.c"
    r7 = r0;
label_19:
    // EBPF_OP_MOV64_REG pc=672 dst=r6 src=r7 offset=0 imm=0
#line 243 "sample/map.c"
    r6 = r7;
    // EBPF_OP_JNE_REG pc=673 dst=r2 src=r3 offset=387 imm=0
#line 243 "sample/map.c"
    if (r2 != r3)
#line 243 "sample/map.c"
        goto label_36;
    // EBPF_OP_MOV64_REG pc=674 dst=r6 src=r7 offset=0 imm=0
#line 243 "sample/map.c"
    r6 = r7;
    // EBPF_OP_JNE_IMM pc=675 dst=r1 src=r0 offset=385 imm=0
#line 243 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 243 "sample/map.c"
        goto label_36;
    // EBPF_OP_MOV64_IMM pc=676 dst=r1 src=r0 offset=0 imm=0
#line 243 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=677 dst=r10 src=r1 offset=-4 imm=0
#line 251 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=678 dst=r2 src=r10 offset=0 imm=0
#line 251 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=679 dst=r2 src=r0 offset=0 imm=-4
#line 251 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=680 dst=r1 src=r0 offset=0 imm=0
#line 251 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=682 dst=r3 src=r0 offset=0 imm=0
#line 251 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=683 dst=r0 src=r0 offset=0 imm=16
#line 251 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 251 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 251 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 251 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=684 dst=r6 src=r0 offset=0 imm=0
#line 251 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=685 dst=r1 src=r6 offset=0 imm=0
#line 251 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=686 dst=r1 src=r0 offset=0 imm=32
#line 251 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=687 dst=r1 src=r0 offset=0 imm=32
#line 251 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=688 dst=r1 src=r0 offset=372 imm=0
#line 251 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 251 "sample/map.c"
        goto label_36;
    // EBPF_OP_MOV64_IMM pc=689 dst=r1 src=r0 offset=0 imm=1
#line 251 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=690 dst=r10 src=r1 offset=-4 imm=0
#line 252 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=691 dst=r2 src=r10 offset=0 imm=0
#line 252 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=692 dst=r2 src=r0 offset=0 imm=-4
#line 252 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=693 dst=r1 src=r0 offset=0 imm=0
#line 252 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=695 dst=r3 src=r0 offset=0 imm=0
#line 252 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=696 dst=r0 src=r0 offset=0 imm=16
#line 252 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 252 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 252 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 252 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=697 dst=r6 src=r0 offset=0 imm=0
#line 252 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=698 dst=r1 src=r6 offset=0 imm=0
#line 252 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=699 dst=r1 src=r0 offset=0 imm=32
#line 252 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=700 dst=r1 src=r0 offset=0 imm=32
#line 252 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=701 dst=r1 src=r0 offset=359 imm=0
#line 252 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 252 "sample/map.c"
        goto label_36;
    // EBPF_OP_MOV64_IMM pc=702 dst=r1 src=r0 offset=0 imm=2
#line 252 "sample/map.c"
    r1 = IMMEDIATE(2);
    // EBPF_OP_STXW pc=703 dst=r10 src=r1 offset=-4 imm=0
#line 253 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=704 dst=r2 src=r10 offset=0 imm=0
#line 253 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=705 dst=r2 src=r0 offset=0 imm=-4
#line 253 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=706 dst=r1 src=r0 offset=0 imm=0
#line 253 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=708 dst=r3 src=r0 offset=0 imm=0
#line 253 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=709 dst=r0 src=r0 offset=0 imm=16
#line 253 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 253 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 253 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 253 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=710 dst=r6 src=r0 offset=0 imm=0
#line 253 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=711 dst=r1 src=r6 offset=0 imm=0
#line 253 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=712 dst=r1 src=r0 offset=0 imm=32
#line 253 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=713 dst=r1 src=r0 offset=0 imm=32
#line 253 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=714 dst=r1 src=r0 offset=346 imm=0
#line 253 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 253 "sample/map.c"
        goto label_36;
    // EBPF_OP_MOV64_IMM pc=715 dst=r1 src=r0 offset=0 imm=3
#line 253 "sample/map.c"
    r1 = IMMEDIATE(3);
    // EBPF_OP_STXW pc=716 dst=r10 src=r1 offset=-4 imm=0
#line 254 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=717 dst=r2 src=r10 offset=0 imm=0
#line 254 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=718 dst=r2 src=r0 offset=0 imm=-4
#line 254 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=719 dst=r1 src=r0 offset=0 imm=0
#line 254 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=721 dst=r3 src=r0 offset=0 imm=0
#line 254 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=722 dst=r0 src=r0 offset=0 imm=16
#line 254 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 254 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 254 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 254 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=723 dst=r6 src=r0 offset=0 imm=0
#line 254 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=724 dst=r1 src=r6 offset=0 imm=0
#line 254 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=725 dst=r1 src=r0 offset=0 imm=32
#line 254 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=726 dst=r1 src=r0 offset=0 imm=32
#line 254 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=727 dst=r1 src=r0 offset=333 imm=0
#line 254 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 254 "sample/map.c"
        goto label_36;
    // EBPF_OP_MOV64_IMM pc=728 dst=r1 src=r0 offset=0 imm=4
#line 254 "sample/map.c"
    r1 = IMMEDIATE(4);
    // EBPF_OP_STXW pc=729 dst=r10 src=r1 offset=-4 imm=0
#line 255 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=730 dst=r2 src=r10 offset=0 imm=0
#line 255 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=731 dst=r2 src=r0 offset=0 imm=-4
#line 255 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=732 dst=r1 src=r0 offset=0 imm=0
#line 255 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=734 dst=r3 src=r0 offset=0 imm=0
#line 255 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=735 dst=r0 src=r0 offset=0 imm=16
#line 255 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 255 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 255 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 255 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=736 dst=r6 src=r0 offset=0 imm=0
#line 255 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=737 dst=r1 src=r6 offset=0 imm=0
#line 255 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=738 dst=r1 src=r0 offset=0 imm=32
#line 255 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=739 dst=r1 src=r0 offset=0 imm=32
#line 255 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=740 dst=r1 src=r0 offset=320 imm=0
#line 255 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 255 "sample/map.c"
        goto label_36;
    // EBPF_OP_MOV64_IMM pc=741 dst=r1 src=r0 offset=0 imm=5
#line 255 "sample/map.c"
    r1 = IMMEDIATE(5);
    // EBPF_OP_STXW pc=742 dst=r10 src=r1 offset=-4 imm=0
#line 256 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=743 dst=r2 src=r10 offset=0 imm=0
#line 256 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=744 dst=r2 src=r0 offset=0 imm=-4
#line 256 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=745 dst=r1 src=r0 offset=0 imm=0
#line 256 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=747 dst=r3 src=r0 offset=0 imm=0
#line 256 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=748 dst=r0 src=r0 offset=0 imm=16
#line 256 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 256 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 256 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 256 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=749 dst=r6 src=r0 offset=0 imm=0
#line 256 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=750 dst=r1 src=r6 offset=0 imm=0
#line 256 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=751 dst=r1 src=r0 offset=0 imm=32
#line 256 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=752 dst=r1 src=r0 offset=0 imm=32
#line 256 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=753 dst=r1 src=r0 offset=307 imm=0
#line 256 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 256 "sample/map.c"
        goto label_36;
    // EBPF_OP_MOV64_IMM pc=754 dst=r1 src=r0 offset=0 imm=6
#line 256 "sample/map.c"
    r1 = IMMEDIATE(6);
    // EBPF_OP_STXW pc=755 dst=r10 src=r1 offset=-4 imm=0
#line 257 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=756 dst=r2 src=r10 offset=0 imm=0
#line 257 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=757 dst=r2 src=r0 offset=0 imm=-4
#line 257 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=758 dst=r1 src=r0 offset=0 imm=0
#line 257 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=760 dst=r3 src=r0 offset=0 imm=0
#line 257 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=761 dst=r0 src=r0 offset=0 imm=16
#line 257 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 257 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 257 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 257 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=762 dst=r6 src=r0 offset=0 imm=0
#line 257 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=763 dst=r1 src=r6 offset=0 imm=0
#line 257 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=764 dst=r1 src=r0 offset=0 imm=32
#line 257 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=765 dst=r1 src=r0 offset=0 imm=32
#line 257 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=766 dst=r1 src=r0 offset=294 imm=0
#line 257 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 257 "sample/map.c"
        goto label_36;
    // EBPF_OP_MOV64_IMM pc=767 dst=r1 src=r0 offset=0 imm=7
#line 257 "sample/map.c"
    r1 = IMMEDIATE(7);
    // EBPF_OP_STXW pc=768 dst=r10 src=r1 offset=-4 imm=0
#line 258 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=769 dst=r2 src=r10 offset=0 imm=0
#line 258 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=770 dst=r2 src=r0 offset=0 imm=-4
#line 258 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=771 dst=r1 src=r0 offset=0 imm=0
#line 258 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=773 dst=r3 src=r0 offset=0 imm=0
#line 258 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=774 dst=r0 src=r0 offset=0 imm=16
#line 258 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 258 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 258 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 258 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=775 dst=r6 src=r0 offset=0 imm=0
#line 258 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=776 dst=r1 src=r6 offset=0 imm=0
#line 258 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=777 dst=r1 src=r0 offset=0 imm=32
#line 258 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=778 dst=r1 src=r0 offset=0 imm=32
#line 258 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=779 dst=r1 src=r0 offset=281 imm=0
#line 258 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 258 "sample/map.c"
        goto label_36;
    // EBPF_OP_MOV64_IMM pc=780 dst=r1 src=r0 offset=0 imm=8
#line 258 "sample/map.c"
    r1 = IMMEDIATE(8);
    // EBPF_OP_STXW pc=781 dst=r10 src=r1 offset=-4 imm=0
#line 259 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=782 dst=r2 src=r10 offset=0 imm=0
#line 259 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=783 dst=r2 src=r0 offset=0 imm=-4
#line 259 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=784 dst=r1 src=r0 offset=0 imm=0
#line 259 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=786 dst=r3 src=r0 offset=0 imm=0
#line 259 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=787 dst=r0 src=r0 offset=0 imm=16
#line 259 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 259 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 259 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 259 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=788 dst=r6 src=r0 offset=0 imm=0
#line 259 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=789 dst=r1 src=r6 offset=0 imm=0
#line 259 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=790 dst=r1 src=r0 offset=0 imm=32
#line 259 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=791 dst=r1 src=r0 offset=0 imm=32
#line 259 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=792 dst=r1 src=r0 offset=268 imm=0
#line 259 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 259 "sample/map.c"
        goto label_36;
    // EBPF_OP_MOV64_IMM pc=793 dst=r1 src=r0 offset=0 imm=9
#line 259 "sample/map.c"
    r1 = IMMEDIATE(9);
    // EBPF_OP_STXW pc=794 dst=r10 src=r1 offset=-4 imm=0
#line 260 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=795 dst=r2 src=r10 offset=0 imm=0
#line 260 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=796 dst=r2 src=r0 offset=0 imm=-4
#line 260 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=797 dst=r1 src=r0 offset=0 imm=0
#line 260 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=799 dst=r3 src=r0 offset=0 imm=0
#line 260 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=800 dst=r0 src=r0 offset=0 imm=16
#line 260 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 260 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 260 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 260 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=801 dst=r6 src=r0 offset=0 imm=0
#line 260 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=802 dst=r1 src=r6 offset=0 imm=0
#line 260 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=803 dst=r1 src=r0 offset=0 imm=32
#line 260 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=804 dst=r1 src=r0 offset=0 imm=32
#line 260 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=805 dst=r1 src=r0 offset=255 imm=0
#line 260 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 260 "sample/map.c"
        goto label_36;
    // EBPF_OP_MOV64_IMM pc=806 dst=r8 src=r0 offset=0 imm=10
#line 260 "sample/map.c"
    r8 = IMMEDIATE(10);
    // EBPF_OP_STXW pc=807 dst=r10 src=r8 offset=-4 imm=0
#line 263 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r8;
    // EBPF_OP_MOV64_REG pc=808 dst=r2 src=r10 offset=0 imm=0
#line 263 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=809 dst=r2 src=r0 offset=0 imm=-4
#line 263 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=810 dst=r1 src=r0 offset=0 imm=0
#line 263 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=812 dst=r3 src=r0 offset=0 imm=0
#line 263 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=813 dst=r0 src=r0 offset=0 imm=16
#line 263 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 263 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 263 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 263 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=814 dst=r6 src=r0 offset=0 imm=0
#line 263 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=815 dst=r1 src=r6 offset=0 imm=0
#line 263 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=816 dst=r1 src=r0 offset=0 imm=32
#line 263 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=817 dst=r1 src=r0 offset=0 imm=32
#line 263 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_LDDW pc=818 dst=r2 src=r0 offset=0 imm=-29
#line 263 "sample/map.c"
    r2 = (uint64_t)4294967267;
    // EBPF_OP_JNE_REG pc=820 dst=r1 src=r2 offset=240 imm=0
#line 263 "sample/map.c"
    if (r1 != r2)
#line 263 "sample/map.c"
        goto label_36;
    // EBPF_OP_STXW pc=821 dst=r10 src=r8 offset=-4 imm=0
#line 264 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r8;
    // EBPF_OP_MOV64_REG pc=822 dst=r2 src=r10 offset=0 imm=0
#line 264 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=823 dst=r2 src=r0 offset=0 imm=-4
#line 264 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=824 dst=r1 src=r0 offset=0 imm=0
#line 264 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=826 dst=r3 src=r0 offset=0 imm=2
#line 264 "sample/map.c"
    r3 = IMMEDIATE(2);
    // EBPF_OP_CALL pc=827 dst=r0 src=r0 offset=0 imm=16
#line 264 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 264 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 264 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 264 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=828 dst=r6 src=r0 offset=0 imm=0
#line 264 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=829 dst=r1 src=r6 offset=0 imm=0
#line 264 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=830 dst=r1 src=r0 offset=0 imm=32
#line 264 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=831 dst=r1 src=r0 offset=0 imm=32
#line 264 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=832 dst=r1 src=r0 offset=1 imm=0
#line 264 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 264 "sample/map.c"
        goto label_20;
    // EBPF_OP_MOV64_REG pc=833 dst=r7 src=r6 offset=0 imm=0
#line 264 "sample/map.c"
    r7 = r6;
label_20:
    // EBPF_OP_JNE_IMM pc=834 dst=r1 src=r0 offset=226 imm=0
#line 264 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 264 "sample/map.c"
        goto label_36;
    // EBPF_OP_MOV64_IMM pc=835 dst=r1 src=r0 offset=0 imm=0
#line 264 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=836 dst=r10 src=r1 offset=-4 imm=0
#line 266 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=837 dst=r2 src=r10 offset=0 imm=0
#line 266 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=838 dst=r2 src=r0 offset=0 imm=-4
#line 266 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=839 dst=r1 src=r0 offset=0 imm=0
#line 266 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=841 dst=r0 src=r0 offset=0 imm=18
#line 266 "sample/map.c"
    r0 = test_maps_helpers[4].address
#line 266 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 266 "sample/map.c"
    if ((test_maps_helpers[4].tail_call) && (r0 == 0))
#line 266 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=842 dst=r6 src=r0 offset=0 imm=0
#line 266 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=843 dst=r1 src=r6 offset=0 imm=0
#line 266 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=844 dst=r1 src=r0 offset=0 imm=32
#line 266 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=845 dst=r1 src=r0 offset=0 imm=32
#line 266 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=846 dst=r1 src=r0 offset=1 imm=0
#line 266 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 266 "sample/map.c"
        goto label_21;
    // EBPF_OP_JA pc=847 dst=r0 src=r0 offset=213 imm=0
#line 266 "sample/map.c"
    goto label_36;
label_21:
    // EBPF_OP_LDXW pc=848 dst=r1 src=r10 offset=-4 imm=0
#line 266 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_LDDW pc=849 dst=r6 src=r0 offset=0 imm=-1
#line 266 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JNE_IMM pc=851 dst=r1 src=r0 offset=-806 imm=1
#line 266 "sample/map.c"
    if (r1 != IMMEDIATE(1))
#line 266 "sample/map.c"
        goto label_1;
    // EBPF_OP_MOV64_IMM pc=852 dst=r1 src=r0 offset=0 imm=0
#line 266 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=853 dst=r10 src=r1 offset=-4 imm=0
#line 274 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=854 dst=r2 src=r10 offset=0 imm=0
#line 274 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=855 dst=r2 src=r0 offset=0 imm=-4
#line 274 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=856 dst=r1 src=r0 offset=0 imm=0
#line 274 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=858 dst=r0 src=r0 offset=0 imm=17
#line 274 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 274 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 274 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 274 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=859 dst=r6 src=r0 offset=0 imm=0
#line 274 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=860 dst=r1 src=r6 offset=0 imm=0
#line 274 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=861 dst=r1 src=r0 offset=0 imm=32
#line 274 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=862 dst=r1 src=r0 offset=0 imm=32
#line 274 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=863 dst=r1 src=r0 offset=1 imm=0
#line 274 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 274 "sample/map.c"
        goto label_22;
    // EBPF_OP_JA pc=864 dst=r0 src=r0 offset=196 imm=0
#line 274 "sample/map.c"
    goto label_36;
label_22:
    // EBPF_OP_LDXW pc=865 dst=r1 src=r10 offset=-4 imm=0
#line 274 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_LDDW pc=866 dst=r6 src=r0 offset=0 imm=-1
#line 274 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JNE_IMM pc=868 dst=r1 src=r0 offset=-823 imm=1
#line 274 "sample/map.c"
    if (r1 != IMMEDIATE(1))
#line 274 "sample/map.c"
        goto label_1;
    // EBPF_OP_MOV64_IMM pc=869 dst=r1 src=r0 offset=0 imm=0
#line 274 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=870 dst=r10 src=r1 offset=-4 imm=0
#line 275 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=871 dst=r2 src=r10 offset=0 imm=0
#line 275 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=872 dst=r2 src=r0 offset=0 imm=-4
#line 275 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=873 dst=r1 src=r0 offset=0 imm=0
#line 275 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=875 dst=r0 src=r0 offset=0 imm=17
#line 275 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 275 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 275 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 275 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=876 dst=r6 src=r0 offset=0 imm=0
#line 275 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=877 dst=r1 src=r6 offset=0 imm=0
#line 275 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=878 dst=r1 src=r0 offset=0 imm=32
#line 275 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=879 dst=r1 src=r0 offset=0 imm=32
#line 275 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=880 dst=r1 src=r0 offset=1 imm=0
#line 275 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 275 "sample/map.c"
        goto label_23;
    // EBPF_OP_JA pc=881 dst=r0 src=r0 offset=179 imm=0
#line 275 "sample/map.c"
    goto label_36;
label_23:
    // EBPF_OP_LDXW pc=882 dst=r1 src=r10 offset=-4 imm=0
#line 275 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_LDDW pc=883 dst=r6 src=r0 offset=0 imm=-1
#line 275 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JNE_IMM pc=885 dst=r1 src=r0 offset=-840 imm=2
#line 275 "sample/map.c"
    if (r1 != IMMEDIATE(2))
#line 275 "sample/map.c"
        goto label_1;
    // EBPF_OP_MOV64_IMM pc=886 dst=r1 src=r0 offset=0 imm=0
#line 275 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=887 dst=r10 src=r1 offset=-4 imm=0
#line 276 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=888 dst=r2 src=r10 offset=0 imm=0
#line 276 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=889 dst=r2 src=r0 offset=0 imm=-4
#line 276 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=890 dst=r1 src=r0 offset=0 imm=0
#line 276 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=892 dst=r0 src=r0 offset=0 imm=17
#line 276 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 276 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 276 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 276 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=893 dst=r6 src=r0 offset=0 imm=0
#line 276 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=894 dst=r1 src=r6 offset=0 imm=0
#line 276 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=895 dst=r1 src=r0 offset=0 imm=32
#line 276 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=896 dst=r1 src=r0 offset=0 imm=32
#line 276 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=897 dst=r1 src=r0 offset=1 imm=0
#line 276 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 276 "sample/map.c"
        goto label_24;
    // EBPF_OP_JA pc=898 dst=r0 src=r0 offset=162 imm=0
#line 276 "sample/map.c"
    goto label_36;
label_24:
    // EBPF_OP_LDXW pc=899 dst=r1 src=r10 offset=-4 imm=0
#line 276 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_LDDW pc=900 dst=r6 src=r0 offset=0 imm=-1
#line 276 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JNE_IMM pc=902 dst=r1 src=r0 offset=-857 imm=3
#line 276 "sample/map.c"
    if (r1 != IMMEDIATE(3))
#line 276 "sample/map.c"
        goto label_1;
    // EBPF_OP_MOV64_IMM pc=903 dst=r1 src=r0 offset=0 imm=0
#line 276 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=904 dst=r10 src=r1 offset=-4 imm=0
#line 277 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=905 dst=r2 src=r10 offset=0 imm=0
#line 277 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=906 dst=r2 src=r0 offset=0 imm=-4
#line 277 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=907 dst=r1 src=r0 offset=0 imm=0
#line 277 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=909 dst=r0 src=r0 offset=0 imm=17
#line 277 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 277 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 277 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 277 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=910 dst=r6 src=r0 offset=0 imm=0
#line 277 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=911 dst=r1 src=r6 offset=0 imm=0
#line 277 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=912 dst=r1 src=r0 offset=0 imm=32
#line 277 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=913 dst=r1 src=r0 offset=0 imm=32
#line 277 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=914 dst=r1 src=r0 offset=1 imm=0
#line 277 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 277 "sample/map.c"
        goto label_25;
    // EBPF_OP_JA pc=915 dst=r0 src=r0 offset=145 imm=0
#line 277 "sample/map.c"
    goto label_36;
label_25:
    // EBPF_OP_LDXW pc=916 dst=r1 src=r10 offset=-4 imm=0
#line 277 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_LDDW pc=917 dst=r6 src=r0 offset=0 imm=-1
#line 277 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JNE_IMM pc=919 dst=r1 src=r0 offset=-874 imm=4
#line 277 "sample/map.c"
    if (r1 != IMMEDIATE(4))
#line 277 "sample/map.c"
        goto label_1;
    // EBPF_OP_MOV64_IMM pc=920 dst=r1 src=r0 offset=0 imm=0
#line 277 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=921 dst=r10 src=r1 offset=-4 imm=0
#line 278 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=922 dst=r2 src=r10 offset=0 imm=0
#line 278 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=923 dst=r2 src=r0 offset=0 imm=-4
#line 278 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=924 dst=r1 src=r0 offset=0 imm=0
#line 278 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=926 dst=r0 src=r0 offset=0 imm=17
#line 278 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 278 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 278 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 278 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=927 dst=r6 src=r0 offset=0 imm=0
#line 278 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=928 dst=r1 src=r6 offset=0 imm=0
#line 278 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=929 dst=r1 src=r0 offset=0 imm=32
#line 278 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=930 dst=r1 src=r0 offset=0 imm=32
#line 278 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=931 dst=r1 src=r0 offset=1 imm=0
#line 278 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 278 "sample/map.c"
        goto label_26;
    // EBPF_OP_JA pc=932 dst=r0 src=r0 offset=128 imm=0
#line 278 "sample/map.c"
    goto label_36;
label_26:
    // EBPF_OP_LDXW pc=933 dst=r1 src=r10 offset=-4 imm=0
#line 278 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_LDDW pc=934 dst=r6 src=r0 offset=0 imm=-1
#line 278 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JNE_IMM pc=936 dst=r1 src=r0 offset=-891 imm=5
#line 278 "sample/map.c"
    if (r1 != IMMEDIATE(5))
#line 278 "sample/map.c"
        goto label_1;
    // EBPF_OP_MOV64_IMM pc=937 dst=r1 src=r0 offset=0 imm=0
#line 278 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=938 dst=r10 src=r1 offset=-4 imm=0
#line 279 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=939 dst=r2 src=r10 offset=0 imm=0
#line 279 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=940 dst=r2 src=r0 offset=0 imm=-4
#line 279 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=941 dst=r1 src=r0 offset=0 imm=0
#line 279 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=943 dst=r0 src=r0 offset=0 imm=17
#line 279 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 279 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 279 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 279 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=944 dst=r6 src=r0 offset=0 imm=0
#line 279 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=945 dst=r1 src=r6 offset=0 imm=0
#line 279 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=946 dst=r1 src=r0 offset=0 imm=32
#line 279 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=947 dst=r1 src=r0 offset=0 imm=32
#line 279 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=948 dst=r1 src=r0 offset=1 imm=0
#line 279 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 279 "sample/map.c"
        goto label_27;
    // EBPF_OP_JA pc=949 dst=r0 src=r0 offset=111 imm=0
#line 279 "sample/map.c"
    goto label_36;
label_27:
    // EBPF_OP_LDXW pc=950 dst=r1 src=r10 offset=-4 imm=0
#line 279 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_LDDW pc=951 dst=r6 src=r0 offset=0 imm=-1
#line 279 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JNE_IMM pc=953 dst=r1 src=r0 offset=-908 imm=6
#line 279 "sample/map.c"
    if (r1 != IMMEDIATE(6))
#line 279 "sample/map.c"
        goto label_1;
    // EBPF_OP_MOV64_IMM pc=954 dst=r1 src=r0 offset=0 imm=0
#line 279 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=955 dst=r10 src=r1 offset=-4 imm=0
#line 280 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=956 dst=r2 src=r10 offset=0 imm=0
#line 280 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=957 dst=r2 src=r0 offset=0 imm=-4
#line 280 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=958 dst=r1 src=r0 offset=0 imm=0
#line 280 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=960 dst=r0 src=r0 offset=0 imm=17
#line 280 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 280 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 280 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 280 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=961 dst=r6 src=r0 offset=0 imm=0
#line 280 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=962 dst=r1 src=r6 offset=0 imm=0
#line 280 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=963 dst=r1 src=r0 offset=0 imm=32
#line 280 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=964 dst=r1 src=r0 offset=0 imm=32
#line 280 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=965 dst=r1 src=r0 offset=1 imm=0
#line 280 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 280 "sample/map.c"
        goto label_28;
    // EBPF_OP_JA pc=966 dst=r0 src=r0 offset=94 imm=0
#line 280 "sample/map.c"
    goto label_36;
label_28:
    // EBPF_OP_LDXW pc=967 dst=r1 src=r10 offset=-4 imm=0
#line 280 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_LDDW pc=968 dst=r6 src=r0 offset=0 imm=-1
#line 280 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JNE_IMM pc=970 dst=r1 src=r0 offset=-925 imm=7
#line 280 "sample/map.c"
    if (r1 != IMMEDIATE(7))
#line 280 "sample/map.c"
        goto label_1;
    // EBPF_OP_MOV64_IMM pc=971 dst=r1 src=r0 offset=0 imm=0
#line 280 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=972 dst=r10 src=r1 offset=-4 imm=0
#line 281 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=973 dst=r2 src=r10 offset=0 imm=0
#line 281 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=974 dst=r2 src=r0 offset=0 imm=-4
#line 281 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=975 dst=r1 src=r0 offset=0 imm=0
#line 281 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=977 dst=r0 src=r0 offset=0 imm=17
#line 281 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 281 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 281 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 281 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=978 dst=r6 src=r0 offset=0 imm=0
#line 281 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=979 dst=r1 src=r6 offset=0 imm=0
#line 281 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=980 dst=r1 src=r0 offset=0 imm=32
#line 281 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=981 dst=r1 src=r0 offset=0 imm=32
#line 281 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=982 dst=r1 src=r0 offset=1 imm=0
#line 281 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 281 "sample/map.c"
        goto label_29;
    // EBPF_OP_JA pc=983 dst=r0 src=r0 offset=77 imm=0
#line 281 "sample/map.c"
    goto label_36;
label_29:
    // EBPF_OP_LDXW pc=984 dst=r1 src=r10 offset=-4 imm=0
#line 281 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_LDDW pc=985 dst=r6 src=r0 offset=0 imm=-1
#line 281 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JNE_IMM pc=987 dst=r1 src=r0 offset=-942 imm=8
#line 281 "sample/map.c"
    if (r1 != IMMEDIATE(8))
#line 281 "sample/map.c"
        goto label_1;
    // EBPF_OP_MOV64_IMM pc=988 dst=r1 src=r0 offset=0 imm=0
#line 281 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=989 dst=r10 src=r1 offset=-4 imm=0
#line 282 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=990 dst=r2 src=r10 offset=0 imm=0
#line 282 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=991 dst=r2 src=r0 offset=0 imm=-4
#line 282 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=992 dst=r1 src=r0 offset=0 imm=0
#line 282 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=994 dst=r0 src=r0 offset=0 imm=17
#line 282 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 282 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 282 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 282 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=995 dst=r6 src=r0 offset=0 imm=0
#line 282 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=996 dst=r1 src=r6 offset=0 imm=0
#line 282 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=997 dst=r1 src=r0 offset=0 imm=32
#line 282 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=998 dst=r1 src=r0 offset=0 imm=32
#line 282 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=999 dst=r1 src=r0 offset=1 imm=0
#line 282 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 282 "sample/map.c"
        goto label_30;
    // EBPF_OP_JA pc=1000 dst=r0 src=r0 offset=60 imm=0
#line 282 "sample/map.c"
    goto label_36;
label_30:
    // EBPF_OP_LDXW pc=1001 dst=r1 src=r10 offset=-4 imm=0
#line 282 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_LDDW pc=1002 dst=r6 src=r0 offset=0 imm=-1
#line 282 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JNE_IMM pc=1004 dst=r1 src=r0 offset=-959 imm=9
#line 282 "sample/map.c"
    if (r1 != IMMEDIATE(9))
#line 282 "sample/map.c"
        goto label_1;
    // EBPF_OP_MOV64_IMM pc=1005 dst=r1 src=r0 offset=0 imm=0
#line 282 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1006 dst=r10 src=r1 offset=-4 imm=0
#line 283 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1007 dst=r2 src=r10 offset=0 imm=0
#line 283 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1008 dst=r2 src=r0 offset=0 imm=-4
#line 283 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1009 dst=r1 src=r0 offset=0 imm=0
#line 283 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=1011 dst=r0 src=r0 offset=0 imm=17
#line 283 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 283 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 283 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 283 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=1012 dst=r6 src=r0 offset=0 imm=0
#line 283 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1013 dst=r1 src=r6 offset=0 imm=0
#line 283 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=1014 dst=r1 src=r0 offset=0 imm=32
#line 283 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1015 dst=r1 src=r0 offset=0 imm=32
#line 283 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=1016 dst=r1 src=r0 offset=1 imm=0
#line 283 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 283 "sample/map.c"
        goto label_31;
    // EBPF_OP_JA pc=1017 dst=r0 src=r0 offset=43 imm=0
#line 283 "sample/map.c"
    goto label_36;
label_31:
    // EBPF_OP_LDXW pc=1018 dst=r1 src=r10 offset=-4 imm=0
#line 283 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_LDDW pc=1019 dst=r6 src=r0 offset=0 imm=-1
#line 283 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JNE_IMM pc=1021 dst=r1 src=r0 offset=-976 imm=10
#line 283 "sample/map.c"
    if (r1 != IMMEDIATE(10))
#line 283 "sample/map.c"
        goto label_1;
    // EBPF_OP_MOV64_IMM pc=1022 dst=r1 src=r0 offset=0 imm=0
#line 283 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1023 dst=r10 src=r1 offset=-4 imm=0
#line 286 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1024 dst=r2 src=r10 offset=0 imm=0
#line 286 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1025 dst=r2 src=r0 offset=0 imm=-4
#line 286 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1026 dst=r1 src=r0 offset=0 imm=0
#line 286 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=1028 dst=r0 src=r0 offset=0 imm=18
#line 286 "sample/map.c"
    r0 = test_maps_helpers[4].address
#line 286 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 286 "sample/map.c"
    if ((test_maps_helpers[4].tail_call) && (r0 == 0))
#line 286 "sample/map.c"
        return 0;
    // EBPF_OP_LDXW pc=1029 dst=r1 src=r10 offset=-4 imm=0
#line 286 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=1030 dst=r6 src=r7 offset=0 imm=0
#line 286 "sample/map.c"
    r6 = r7;
    // EBPF_OP_JEQ_IMM pc=1031 dst=r1 src=r0 offset=1 imm=0
#line 286 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 286 "sample/map.c"
        goto label_32;
    // EBPF_OP_MOV64_IMM pc=1032 dst=r6 src=r0 offset=0 imm=-1
#line 286 "sample/map.c"
    r6 = IMMEDIATE(-1);
label_32:
    // EBPF_OP_MOV64_REG pc=1033 dst=r2 src=r0 offset=0 imm=0
#line 286 "sample/map.c"
    r2 = r0;
    // EBPF_OP_LSH64_IMM pc=1034 dst=r2 src=r0 offset=0 imm=32
#line 286 "sample/map.c"
    r2 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1035 dst=r2 src=r0 offset=0 imm=32
#line 286 "sample/map.c"
    r2 >>= IMMEDIATE(32);
    // EBPF_OP_LDDW pc=1036 dst=r3 src=r0 offset=0 imm=-7
#line 286 "sample/map.c"
    r3 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=1038 dst=r2 src=r3 offset=1 imm=0
#line 286 "sample/map.c"
    if (r2 == r3)
#line 286 "sample/map.c"
        goto label_33;
    // EBPF_OP_MOV64_REG pc=1039 dst=r6 src=r0 offset=0 imm=0
#line 286 "sample/map.c"
    r6 = r0;
label_33:
    // EBPF_OP_JNE_REG pc=1040 dst=r2 src=r3 offset=20 imm=0
#line 286 "sample/map.c"
    if (r2 != r3)
#line 286 "sample/map.c"
        goto label_36;
    // EBPF_OP_JNE_IMM pc=1041 dst=r1 src=r0 offset=19 imm=0
#line 286 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 286 "sample/map.c"
        goto label_36;
    // EBPF_OP_MOV64_IMM pc=1042 dst=r1 src=r0 offset=0 imm=0
#line 286 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1043 dst=r10 src=r1 offset=-4 imm=0
#line 287 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1044 dst=r2 src=r10 offset=0 imm=0
#line 287 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1045 dst=r2 src=r0 offset=0 imm=-4
#line 287 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1046 dst=r1 src=r0 offset=0 imm=0
#line 287 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=1048 dst=r0 src=r0 offset=0 imm=17
#line 287 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 287 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 287 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 287 "sample/map.c"
        return 0;
    // EBPF_OP_LDXW pc=1049 dst=r1 src=r10 offset=-4 imm=0
#line 287 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1050 dst=r1 src=r0 offset=1 imm=0
#line 287 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 287 "sample/map.c"
        goto label_34;
    // EBPF_OP_MOV64_IMM pc=1051 dst=r6 src=r0 offset=0 imm=-1
#line 287 "sample/map.c"
    r6 = IMMEDIATE(-1);
label_34:
    // EBPF_OP_MOV64_REG pc=1052 dst=r2 src=r0 offset=0 imm=0
#line 287 "sample/map.c"
    r2 = r0;
    // EBPF_OP_LSH64_IMM pc=1053 dst=r2 src=r0 offset=0 imm=32
#line 287 "sample/map.c"
    r2 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1054 dst=r2 src=r0 offset=0 imm=32
#line 287 "sample/map.c"
    r2 >>= IMMEDIATE(32);
    // EBPF_OP_LDDW pc=1055 dst=r3 src=r0 offset=0 imm=-7
#line 287 "sample/map.c"
    r3 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=1057 dst=r2 src=r3 offset=1 imm=0
#line 287 "sample/map.c"
    if (r2 == r3)
#line 287 "sample/map.c"
        goto label_35;
    // EBPF_OP_MOV64_REG pc=1058 dst=r6 src=r0 offset=0 imm=0
#line 287 "sample/map.c"
    r6 = r0;
label_35:
    // EBPF_OP_JNE_REG pc=1059 dst=r2 src=r3 offset=1 imm=0
#line 287 "sample/map.c"
    if (r2 != r3)
#line 287 "sample/map.c"
        goto label_36;
    // EBPF_OP_JEQ_IMM pc=1060 dst=r1 src=r0 offset=5 imm=0
#line 287 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 287 "sample/map.c"
        goto label_37;
label_36:
    // EBPF_OP_MOV64_REG pc=1061 dst=r1 src=r6 offset=0 imm=0
#line 305 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=1062 dst=r1 src=r0 offset=0 imm=32
#line 305 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=1063 dst=r1 src=r0 offset=0 imm=32
#line 305 "sample/map.c"
    r1 = (int64_t)r1 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_IMM pc=1064 dst=r2 src=r0 offset=0 imm=0
#line 305 "sample/map.c"
    r2 = IMMEDIATE(0);
    // EBPF_OP_JSGT_REG pc=1065 dst=r2 src=r1 offset=-1020 imm=0
#line 305 "sample/map.c"
    if ((int64_t)r2 > (int64_t)r1)
#line 305 "sample/map.c"
        goto label_1;
label_37:
    // EBPF_OP_MOV64_IMM pc=1066 dst=r1 src=r0 offset=0 imm=0
#line 305 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1067 dst=r10 src=r1 offset=-4 imm=0
#line 242 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1068 dst=r2 src=r10 offset=0 imm=0
#line 242 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1069 dst=r2 src=r0 offset=0 imm=-4
#line 242 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1070 dst=r1 src=r0 offset=0 imm=0
#line 242 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=1072 dst=r0 src=r0 offset=0 imm=18
#line 242 "sample/map.c"
    r0 = test_maps_helpers[4].address
#line 242 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 242 "sample/map.c"
    if ((test_maps_helpers[4].tail_call) && (r0 == 0))
#line 242 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=1073 dst=r1 src=r0 offset=0 imm=0
#line 242 "sample/map.c"
    r1 = r0;
    // EBPF_OP_LSH64_IMM pc=1074 dst=r1 src=r0 offset=0 imm=32
#line 242 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1075 dst=r1 src=r0 offset=0 imm=32
#line 242 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_MOV64_IMM pc=1076 dst=r7 src=r0 offset=0 imm=-1
#line 242 "sample/map.c"
    r7 = IMMEDIATE(-1);
    // EBPF_OP_LDDW pc=1077 dst=r2 src=r0 offset=0 imm=-7
#line 242 "sample/map.c"
    r2 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=1079 dst=r1 src=r2 offset=1 imm=0
#line 242 "sample/map.c"
    if (r1 == r2)
#line 242 "sample/map.c"
        goto label_38;
    // EBPF_OP_MOV64_REG pc=1080 dst=r7 src=r0 offset=0 imm=0
#line 242 "sample/map.c"
    r7 = r0;
label_38:
    // EBPF_OP_JNE_REG pc=1081 dst=r1 src=r2 offset=380 imm=0
#line 242 "sample/map.c"
    if (r1 != r2)
#line 242 "sample/map.c"
        goto label_58;
    // EBPF_OP_LDXW pc=1082 dst=r1 src=r10 offset=-4 imm=0
#line 242 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=1083 dst=r1 src=r0 offset=378 imm=0
#line 242 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 242 "sample/map.c"
        goto label_58;
    // EBPF_OP_MOV64_IMM pc=1084 dst=r1 src=r0 offset=0 imm=0
#line 242 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1085 dst=r10 src=r1 offset=-4 imm=0
#line 243 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1086 dst=r2 src=r10 offset=0 imm=0
#line 243 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1087 dst=r2 src=r0 offset=0 imm=-4
#line 243 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1088 dst=r1 src=r0 offset=0 imm=0
#line 243 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=1090 dst=r0 src=r0 offset=0 imm=17
#line 243 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 243 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 243 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 243 "sample/map.c"
        return 0;
    // EBPF_OP_LDXW pc=1091 dst=r1 src=r10 offset=-4 imm=0
#line 243 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=1092 dst=r6 src=r7 offset=0 imm=0
#line 243 "sample/map.c"
    r6 = r7;
    // EBPF_OP_JEQ_IMM pc=1093 dst=r1 src=r0 offset=1 imm=0
#line 243 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 243 "sample/map.c"
        goto label_39;
    // EBPF_OP_MOV64_IMM pc=1094 dst=r6 src=r0 offset=0 imm=-1
#line 243 "sample/map.c"
    r6 = IMMEDIATE(-1);
label_39:
    // EBPF_OP_MOV64_REG pc=1095 dst=r2 src=r0 offset=0 imm=0
#line 243 "sample/map.c"
    r2 = r0;
    // EBPF_OP_LSH64_IMM pc=1096 dst=r2 src=r0 offset=0 imm=32
#line 243 "sample/map.c"
    r2 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1097 dst=r2 src=r0 offset=0 imm=32
#line 243 "sample/map.c"
    r2 >>= IMMEDIATE(32);
    // EBPF_OP_LDDW pc=1098 dst=r3 src=r0 offset=0 imm=-7
#line 243 "sample/map.c"
    r3 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=1100 dst=r2 src=r3 offset=1 imm=0
#line 243 "sample/map.c"
    if (r2 == r3)
#line 243 "sample/map.c"
        goto label_40;
    // EBPF_OP_MOV64_REG pc=1101 dst=r6 src=r0 offset=0 imm=0
#line 243 "sample/map.c"
    r6 = r0;
label_40:
    // EBPF_OP_MOV64_REG pc=1102 dst=r7 src=r6 offset=0 imm=0
#line 243 "sample/map.c"
    r7 = r6;
    // EBPF_OP_JNE_REG pc=1103 dst=r2 src=r3 offset=358 imm=0
#line 243 "sample/map.c"
    if (r2 != r3)
#line 243 "sample/map.c"
        goto label_58;
    // EBPF_OP_MOV64_REG pc=1104 dst=r7 src=r6 offset=0 imm=0
#line 243 "sample/map.c"
    r7 = r6;
    // EBPF_OP_JNE_IMM pc=1105 dst=r1 src=r0 offset=356 imm=0
#line 243 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 243 "sample/map.c"
        goto label_58;
    // EBPF_OP_MOV64_IMM pc=1106 dst=r1 src=r0 offset=0 imm=0
#line 243 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1107 dst=r10 src=r1 offset=-4 imm=0
#line 251 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1108 dst=r2 src=r10 offset=0 imm=0
#line 251 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1109 dst=r2 src=r0 offset=0 imm=-4
#line 251 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1110 dst=r1 src=r0 offset=0 imm=0
#line 251 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=1112 dst=r3 src=r0 offset=0 imm=0
#line 251 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1113 dst=r0 src=r0 offset=0 imm=16
#line 251 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 251 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 251 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 251 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=1114 dst=r7 src=r0 offset=0 imm=0
#line 251 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1115 dst=r1 src=r7 offset=0 imm=0
#line 251 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=1116 dst=r1 src=r0 offset=0 imm=32
#line 251 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1117 dst=r1 src=r0 offset=0 imm=32
#line 251 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1118 dst=r1 src=r0 offset=343 imm=0
#line 251 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 251 "sample/map.c"
        goto label_58;
    // EBPF_OP_MOV64_IMM pc=1119 dst=r1 src=r0 offset=0 imm=1
#line 251 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=1120 dst=r10 src=r1 offset=-4 imm=0
#line 252 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1121 dst=r2 src=r10 offset=0 imm=0
#line 252 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1122 dst=r2 src=r0 offset=0 imm=-4
#line 252 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1123 dst=r1 src=r0 offset=0 imm=0
#line 252 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=1125 dst=r3 src=r0 offset=0 imm=0
#line 252 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1126 dst=r0 src=r0 offset=0 imm=16
#line 252 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 252 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 252 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 252 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=1127 dst=r7 src=r0 offset=0 imm=0
#line 252 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1128 dst=r1 src=r7 offset=0 imm=0
#line 252 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=1129 dst=r1 src=r0 offset=0 imm=32
#line 252 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1130 dst=r1 src=r0 offset=0 imm=32
#line 252 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1131 dst=r1 src=r0 offset=330 imm=0
#line 252 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 252 "sample/map.c"
        goto label_58;
    // EBPF_OP_MOV64_IMM pc=1132 dst=r1 src=r0 offset=0 imm=2
#line 252 "sample/map.c"
    r1 = IMMEDIATE(2);
    // EBPF_OP_STXW pc=1133 dst=r10 src=r1 offset=-4 imm=0
#line 253 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1134 dst=r2 src=r10 offset=0 imm=0
#line 253 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1135 dst=r2 src=r0 offset=0 imm=-4
#line 253 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1136 dst=r1 src=r0 offset=0 imm=0
#line 253 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=1138 dst=r3 src=r0 offset=0 imm=0
#line 253 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1139 dst=r0 src=r0 offset=0 imm=16
#line 253 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 253 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 253 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 253 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=1140 dst=r7 src=r0 offset=0 imm=0
#line 253 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1141 dst=r1 src=r7 offset=0 imm=0
#line 253 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=1142 dst=r1 src=r0 offset=0 imm=32
#line 253 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1143 dst=r1 src=r0 offset=0 imm=32
#line 253 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1144 dst=r1 src=r0 offset=317 imm=0
#line 253 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 253 "sample/map.c"
        goto label_58;
    // EBPF_OP_MOV64_IMM pc=1145 dst=r1 src=r0 offset=0 imm=3
#line 253 "sample/map.c"
    r1 = IMMEDIATE(3);
    // EBPF_OP_STXW pc=1146 dst=r10 src=r1 offset=-4 imm=0
#line 254 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1147 dst=r2 src=r10 offset=0 imm=0
#line 254 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1148 dst=r2 src=r0 offset=0 imm=-4
#line 254 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1149 dst=r1 src=r0 offset=0 imm=0
#line 254 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=1151 dst=r3 src=r0 offset=0 imm=0
#line 254 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1152 dst=r0 src=r0 offset=0 imm=16
#line 254 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 254 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 254 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 254 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=1153 dst=r7 src=r0 offset=0 imm=0
#line 254 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1154 dst=r1 src=r7 offset=0 imm=0
#line 254 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=1155 dst=r1 src=r0 offset=0 imm=32
#line 254 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1156 dst=r1 src=r0 offset=0 imm=32
#line 254 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1157 dst=r1 src=r0 offset=304 imm=0
#line 254 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 254 "sample/map.c"
        goto label_58;
    // EBPF_OP_MOV64_IMM pc=1158 dst=r1 src=r0 offset=0 imm=4
#line 254 "sample/map.c"
    r1 = IMMEDIATE(4);
    // EBPF_OP_STXW pc=1159 dst=r10 src=r1 offset=-4 imm=0
#line 255 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1160 dst=r2 src=r10 offset=0 imm=0
#line 255 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1161 dst=r2 src=r0 offset=0 imm=-4
#line 255 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1162 dst=r1 src=r0 offset=0 imm=0
#line 255 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=1164 dst=r3 src=r0 offset=0 imm=0
#line 255 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1165 dst=r0 src=r0 offset=0 imm=16
#line 255 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 255 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 255 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 255 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=1166 dst=r7 src=r0 offset=0 imm=0
#line 255 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1167 dst=r1 src=r7 offset=0 imm=0
#line 255 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=1168 dst=r1 src=r0 offset=0 imm=32
#line 255 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1169 dst=r1 src=r0 offset=0 imm=32
#line 255 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1170 dst=r1 src=r0 offset=291 imm=0
#line 255 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 255 "sample/map.c"
        goto label_58;
    // EBPF_OP_MOV64_IMM pc=1171 dst=r1 src=r0 offset=0 imm=5
#line 255 "sample/map.c"
    r1 = IMMEDIATE(5);
    // EBPF_OP_STXW pc=1172 dst=r10 src=r1 offset=-4 imm=0
#line 256 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1173 dst=r2 src=r10 offset=0 imm=0
#line 256 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1174 dst=r2 src=r0 offset=0 imm=-4
#line 256 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1175 dst=r1 src=r0 offset=0 imm=0
#line 256 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=1177 dst=r3 src=r0 offset=0 imm=0
#line 256 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1178 dst=r0 src=r0 offset=0 imm=16
#line 256 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 256 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 256 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 256 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=1179 dst=r7 src=r0 offset=0 imm=0
#line 256 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1180 dst=r1 src=r7 offset=0 imm=0
#line 256 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=1181 dst=r1 src=r0 offset=0 imm=32
#line 256 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1182 dst=r1 src=r0 offset=0 imm=32
#line 256 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1183 dst=r1 src=r0 offset=278 imm=0
#line 256 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 256 "sample/map.c"
        goto label_58;
    // EBPF_OP_MOV64_IMM pc=1184 dst=r1 src=r0 offset=0 imm=6
#line 256 "sample/map.c"
    r1 = IMMEDIATE(6);
    // EBPF_OP_STXW pc=1185 dst=r10 src=r1 offset=-4 imm=0
#line 257 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1186 dst=r2 src=r10 offset=0 imm=0
#line 257 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1187 dst=r2 src=r0 offset=0 imm=-4
#line 257 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1188 dst=r1 src=r0 offset=0 imm=0
#line 257 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=1190 dst=r3 src=r0 offset=0 imm=0
#line 257 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1191 dst=r0 src=r0 offset=0 imm=16
#line 257 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 257 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 257 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 257 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=1192 dst=r7 src=r0 offset=0 imm=0
#line 257 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1193 dst=r1 src=r7 offset=0 imm=0
#line 257 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=1194 dst=r1 src=r0 offset=0 imm=32
#line 257 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1195 dst=r1 src=r0 offset=0 imm=32
#line 257 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1196 dst=r1 src=r0 offset=265 imm=0
#line 257 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 257 "sample/map.c"
        goto label_58;
    // EBPF_OP_MOV64_IMM pc=1197 dst=r1 src=r0 offset=0 imm=7
#line 257 "sample/map.c"
    r1 = IMMEDIATE(7);
    // EBPF_OP_STXW pc=1198 dst=r10 src=r1 offset=-4 imm=0
#line 258 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1199 dst=r2 src=r10 offset=0 imm=0
#line 258 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1200 dst=r2 src=r0 offset=0 imm=-4
#line 258 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1201 dst=r1 src=r0 offset=0 imm=0
#line 258 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=1203 dst=r3 src=r0 offset=0 imm=0
#line 258 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1204 dst=r0 src=r0 offset=0 imm=16
#line 258 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 258 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 258 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 258 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=1205 dst=r7 src=r0 offset=0 imm=0
#line 258 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1206 dst=r1 src=r7 offset=0 imm=0
#line 258 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=1207 dst=r1 src=r0 offset=0 imm=32
#line 258 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1208 dst=r1 src=r0 offset=0 imm=32
#line 258 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1209 dst=r1 src=r0 offset=252 imm=0
#line 258 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 258 "sample/map.c"
        goto label_58;
    // EBPF_OP_MOV64_IMM pc=1210 dst=r1 src=r0 offset=0 imm=8
#line 258 "sample/map.c"
    r1 = IMMEDIATE(8);
    // EBPF_OP_STXW pc=1211 dst=r10 src=r1 offset=-4 imm=0
#line 259 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1212 dst=r2 src=r10 offset=0 imm=0
#line 259 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1213 dst=r2 src=r0 offset=0 imm=-4
#line 259 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1214 dst=r1 src=r0 offset=0 imm=0
#line 259 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=1216 dst=r3 src=r0 offset=0 imm=0
#line 259 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1217 dst=r0 src=r0 offset=0 imm=16
#line 259 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 259 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 259 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 259 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=1218 dst=r7 src=r0 offset=0 imm=0
#line 259 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1219 dst=r1 src=r7 offset=0 imm=0
#line 259 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=1220 dst=r1 src=r0 offset=0 imm=32
#line 259 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1221 dst=r1 src=r0 offset=0 imm=32
#line 259 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1222 dst=r1 src=r0 offset=239 imm=0
#line 259 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 259 "sample/map.c"
        goto label_58;
    // EBPF_OP_MOV64_IMM pc=1223 dst=r1 src=r0 offset=0 imm=9
#line 259 "sample/map.c"
    r1 = IMMEDIATE(9);
    // EBPF_OP_STXW pc=1224 dst=r10 src=r1 offset=-4 imm=0
#line 260 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1225 dst=r2 src=r10 offset=0 imm=0
#line 260 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1226 dst=r2 src=r0 offset=0 imm=-4
#line 260 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1227 dst=r1 src=r0 offset=0 imm=0
#line 260 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=1229 dst=r3 src=r0 offset=0 imm=0
#line 260 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1230 dst=r0 src=r0 offset=0 imm=16
#line 260 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 260 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 260 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 260 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=1231 dst=r7 src=r0 offset=0 imm=0
#line 260 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1232 dst=r1 src=r7 offset=0 imm=0
#line 260 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=1233 dst=r1 src=r0 offset=0 imm=32
#line 260 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1234 dst=r1 src=r0 offset=0 imm=32
#line 260 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1235 dst=r1 src=r0 offset=226 imm=0
#line 260 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 260 "sample/map.c"
        goto label_58;
    // EBPF_OP_MOV64_IMM pc=1236 dst=r8 src=r0 offset=0 imm=10
#line 260 "sample/map.c"
    r8 = IMMEDIATE(10);
    // EBPF_OP_STXW pc=1237 dst=r10 src=r8 offset=-4 imm=0
#line 263 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r8;
    // EBPF_OP_MOV64_REG pc=1238 dst=r2 src=r10 offset=0 imm=0
#line 263 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1239 dst=r2 src=r0 offset=0 imm=-4
#line 263 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1240 dst=r1 src=r0 offset=0 imm=0
#line 263 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=1242 dst=r3 src=r0 offset=0 imm=0
#line 263 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1243 dst=r0 src=r0 offset=0 imm=16
#line 263 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 263 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 263 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 263 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=1244 dst=r7 src=r0 offset=0 imm=0
#line 263 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1245 dst=r1 src=r7 offset=0 imm=0
#line 263 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=1246 dst=r1 src=r0 offset=0 imm=32
#line 263 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1247 dst=r1 src=r0 offset=0 imm=32
#line 263 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_LDDW pc=1248 dst=r2 src=r0 offset=0 imm=-29
#line 263 "sample/map.c"
    r2 = (uint64_t)4294967267;
    // EBPF_OP_JNE_REG pc=1250 dst=r1 src=r2 offset=211 imm=0
#line 263 "sample/map.c"
    if (r1 != r2)
#line 263 "sample/map.c"
        goto label_58;
    // EBPF_OP_STXW pc=1251 dst=r10 src=r8 offset=-4 imm=0
#line 264 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r8;
    // EBPF_OP_MOV64_REG pc=1252 dst=r2 src=r10 offset=0 imm=0
#line 264 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1253 dst=r2 src=r0 offset=0 imm=-4
#line 264 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1254 dst=r1 src=r0 offset=0 imm=0
#line 264 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=1256 dst=r3 src=r0 offset=0 imm=2
#line 264 "sample/map.c"
    r3 = IMMEDIATE(2);
    // EBPF_OP_CALL pc=1257 dst=r0 src=r0 offset=0 imm=16
#line 264 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 264 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 264 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 264 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=1258 dst=r7 src=r0 offset=0 imm=0
#line 264 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1259 dst=r1 src=r7 offset=0 imm=0
#line 264 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=1260 dst=r1 src=r0 offset=0 imm=32
#line 264 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1261 dst=r1 src=r0 offset=0 imm=32
#line 264 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=1262 dst=r1 src=r0 offset=1 imm=0
#line 264 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 264 "sample/map.c"
        goto label_41;
    // EBPF_OP_MOV64_REG pc=1263 dst=r6 src=r7 offset=0 imm=0
#line 264 "sample/map.c"
    r6 = r7;
label_41:
    // EBPF_OP_JNE_IMM pc=1264 dst=r1 src=r0 offset=197 imm=0
#line 264 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 264 "sample/map.c"
        goto label_58;
    // EBPF_OP_MOV64_IMM pc=1265 dst=r1 src=r0 offset=0 imm=0
#line 264 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1266 dst=r10 src=r1 offset=-4 imm=0
#line 266 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1267 dst=r2 src=r10 offset=0 imm=0
#line 266 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1268 dst=r2 src=r0 offset=0 imm=-4
#line 266 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1269 dst=r1 src=r0 offset=0 imm=0
#line 266 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=1271 dst=r0 src=r0 offset=0 imm=18
#line 266 "sample/map.c"
    r0 = test_maps_helpers[4].address
#line 266 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 266 "sample/map.c"
    if ((test_maps_helpers[4].tail_call) && (r0 == 0))
#line 266 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=1272 dst=r7 src=r0 offset=0 imm=0
#line 266 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1273 dst=r1 src=r7 offset=0 imm=0
#line 266 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=1274 dst=r1 src=r0 offset=0 imm=32
#line 266 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1275 dst=r1 src=r0 offset=0 imm=32
#line 266 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=1276 dst=r1 src=r0 offset=1 imm=0
#line 266 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 266 "sample/map.c"
        goto label_42;
    // EBPF_OP_JA pc=1277 dst=r0 src=r0 offset=184 imm=0
#line 266 "sample/map.c"
    goto label_58;
label_42:
    // EBPF_OP_LDDW pc=1278 dst=r7 src=r0 offset=0 imm=-1
#line 266 "sample/map.c"
    r7 = (uint64_t)4294967295;
    // EBPF_OP_LDXW pc=1280 dst=r1 src=r10 offset=-4 imm=0
#line 266 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=1281 dst=r1 src=r0 offset=185 imm=10
#line 266 "sample/map.c"
    if (r1 != IMMEDIATE(10))
#line 266 "sample/map.c"
        goto label_59;
    // EBPF_OP_MOV64_IMM pc=1282 dst=r1 src=r0 offset=0 imm=0
#line 266 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1283 dst=r10 src=r1 offset=-4 imm=0
#line 274 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1284 dst=r2 src=r10 offset=0 imm=0
#line 274 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1285 dst=r2 src=r0 offset=0 imm=-4
#line 274 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1286 dst=r1 src=r0 offset=0 imm=0
#line 274 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=1288 dst=r0 src=r0 offset=0 imm=17
#line 274 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 274 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 274 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 274 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=1289 dst=r1 src=r0 offset=0 imm=0
#line 274 "sample/map.c"
    r1 = r0;
    // EBPF_OP_LSH64_IMM pc=1290 dst=r1 src=r0 offset=0 imm=32
#line 274 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1291 dst=r1 src=r0 offset=0 imm=32
#line 274 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=1292 dst=r1 src=r0 offset=2 imm=0
#line 274 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 274 "sample/map.c"
        goto label_44;
label_43:
    // EBPF_OP_MOV64_REG pc=1293 dst=r7 src=r0 offset=0 imm=0
#line 274 "sample/map.c"
    r7 = r0;
    // EBPF_OP_JA pc=1294 dst=r0 src=r0 offset=167 imm=0
#line 274 "sample/map.c"
    goto label_58;
label_44:
    // EBPF_OP_LDXW pc=1295 dst=r1 src=r10 offset=-4 imm=0
#line 274 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=1296 dst=r1 src=r0 offset=170 imm=10
#line 274 "sample/map.c"
    if (r1 != IMMEDIATE(10))
#line 274 "sample/map.c"
        goto label_59;
    // EBPF_OP_MOV64_IMM pc=1297 dst=r1 src=r0 offset=0 imm=0
#line 274 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1298 dst=r10 src=r1 offset=-4 imm=0
#line 275 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1299 dst=r2 src=r10 offset=0 imm=0
#line 275 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1300 dst=r2 src=r0 offset=0 imm=-4
#line 275 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1301 dst=r1 src=r0 offset=0 imm=0
#line 275 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=1303 dst=r0 src=r0 offset=0 imm=17
#line 275 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 275 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 275 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 275 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=1304 dst=r1 src=r0 offset=0 imm=0
#line 275 "sample/map.c"
    r1 = r0;
    // EBPF_OP_LSH64_IMM pc=1305 dst=r1 src=r0 offset=0 imm=32
#line 275 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1306 dst=r1 src=r0 offset=0 imm=32
#line 275 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=1307 dst=r1 src=r0 offset=1 imm=0
#line 275 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 275 "sample/map.c"
        goto label_45;
    // EBPF_OP_JA pc=1308 dst=r0 src=r0 offset=-16 imm=0
#line 275 "sample/map.c"
    goto label_43;
label_45:
    // EBPF_OP_LDXW pc=1309 dst=r1 src=r10 offset=-4 imm=0
#line 275 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=1310 dst=r1 src=r0 offset=156 imm=9
#line 275 "sample/map.c"
    if (r1 != IMMEDIATE(9))
#line 275 "sample/map.c"
        goto label_59;
    // EBPF_OP_MOV64_IMM pc=1311 dst=r1 src=r0 offset=0 imm=0
#line 275 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1312 dst=r10 src=r1 offset=-4 imm=0
#line 276 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1313 dst=r2 src=r10 offset=0 imm=0
#line 276 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1314 dst=r2 src=r0 offset=0 imm=-4
#line 276 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1315 dst=r1 src=r0 offset=0 imm=0
#line 276 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=1317 dst=r0 src=r0 offset=0 imm=17
#line 276 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 276 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 276 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 276 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=1318 dst=r1 src=r0 offset=0 imm=0
#line 276 "sample/map.c"
    r1 = r0;
    // EBPF_OP_LSH64_IMM pc=1319 dst=r1 src=r0 offset=0 imm=32
#line 276 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1320 dst=r1 src=r0 offset=0 imm=32
#line 276 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=1321 dst=r1 src=r0 offset=1 imm=0
#line 276 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 276 "sample/map.c"
        goto label_46;
    // EBPF_OP_JA pc=1322 dst=r0 src=r0 offset=-30 imm=0
#line 276 "sample/map.c"
    goto label_43;
label_46:
    // EBPF_OP_LDXW pc=1323 dst=r1 src=r10 offset=-4 imm=0
#line 276 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=1324 dst=r1 src=r0 offset=142 imm=8
#line 276 "sample/map.c"
    if (r1 != IMMEDIATE(8))
#line 276 "sample/map.c"
        goto label_59;
    // EBPF_OP_MOV64_IMM pc=1325 dst=r1 src=r0 offset=0 imm=0
#line 276 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1326 dst=r10 src=r1 offset=-4 imm=0
#line 277 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1327 dst=r2 src=r10 offset=0 imm=0
#line 277 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1328 dst=r2 src=r0 offset=0 imm=-4
#line 277 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1329 dst=r1 src=r0 offset=0 imm=0
#line 277 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=1331 dst=r0 src=r0 offset=0 imm=17
#line 277 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 277 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 277 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 277 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=1332 dst=r1 src=r0 offset=0 imm=0
#line 277 "sample/map.c"
    r1 = r0;
    // EBPF_OP_LSH64_IMM pc=1333 dst=r1 src=r0 offset=0 imm=32
#line 277 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1334 dst=r1 src=r0 offset=0 imm=32
#line 277 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=1335 dst=r1 src=r0 offset=1 imm=0
#line 277 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 277 "sample/map.c"
        goto label_47;
    // EBPF_OP_JA pc=1336 dst=r0 src=r0 offset=-44 imm=0
#line 277 "sample/map.c"
    goto label_43;
label_47:
    // EBPF_OP_LDXW pc=1337 dst=r1 src=r10 offset=-4 imm=0
#line 277 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=1338 dst=r1 src=r0 offset=128 imm=7
#line 277 "sample/map.c"
    if (r1 != IMMEDIATE(7))
#line 277 "sample/map.c"
        goto label_59;
    // EBPF_OP_MOV64_IMM pc=1339 dst=r1 src=r0 offset=0 imm=0
#line 277 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1340 dst=r10 src=r1 offset=-4 imm=0
#line 278 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1341 dst=r2 src=r10 offset=0 imm=0
#line 278 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1342 dst=r2 src=r0 offset=0 imm=-4
#line 278 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1343 dst=r1 src=r0 offset=0 imm=0
#line 278 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=1345 dst=r0 src=r0 offset=0 imm=17
#line 278 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 278 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 278 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 278 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=1346 dst=r1 src=r0 offset=0 imm=0
#line 278 "sample/map.c"
    r1 = r0;
    // EBPF_OP_LSH64_IMM pc=1347 dst=r1 src=r0 offset=0 imm=32
#line 278 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1348 dst=r1 src=r0 offset=0 imm=32
#line 278 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=1349 dst=r1 src=r0 offset=1 imm=0
#line 278 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 278 "sample/map.c"
        goto label_48;
    // EBPF_OP_JA pc=1350 dst=r0 src=r0 offset=-58 imm=0
#line 278 "sample/map.c"
    goto label_43;
label_48:
    // EBPF_OP_LDXW pc=1351 dst=r1 src=r10 offset=-4 imm=0
#line 278 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=1352 dst=r1 src=r0 offset=114 imm=6
#line 278 "sample/map.c"
    if (r1 != IMMEDIATE(6))
#line 278 "sample/map.c"
        goto label_59;
    // EBPF_OP_MOV64_IMM pc=1353 dst=r1 src=r0 offset=0 imm=0
#line 278 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1354 dst=r10 src=r1 offset=-4 imm=0
#line 279 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1355 dst=r2 src=r10 offset=0 imm=0
#line 279 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1356 dst=r2 src=r0 offset=0 imm=-4
#line 279 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1357 dst=r1 src=r0 offset=0 imm=0
#line 279 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=1359 dst=r0 src=r0 offset=0 imm=17
#line 279 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 279 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 279 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 279 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=1360 dst=r1 src=r0 offset=0 imm=0
#line 279 "sample/map.c"
    r1 = r0;
    // EBPF_OP_LSH64_IMM pc=1361 dst=r1 src=r0 offset=0 imm=32
#line 279 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1362 dst=r1 src=r0 offset=0 imm=32
#line 279 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=1363 dst=r1 src=r0 offset=1 imm=0
#line 279 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 279 "sample/map.c"
        goto label_49;
    // EBPF_OP_JA pc=1364 dst=r0 src=r0 offset=-72 imm=0
#line 279 "sample/map.c"
    goto label_43;
label_49:
    // EBPF_OP_LDXW pc=1365 dst=r1 src=r10 offset=-4 imm=0
#line 279 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=1366 dst=r1 src=r0 offset=100 imm=5
#line 279 "sample/map.c"
    if (r1 != IMMEDIATE(5))
#line 279 "sample/map.c"
        goto label_59;
    // EBPF_OP_MOV64_IMM pc=1367 dst=r1 src=r0 offset=0 imm=0
#line 279 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1368 dst=r10 src=r1 offset=-4 imm=0
#line 280 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1369 dst=r2 src=r10 offset=0 imm=0
#line 280 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1370 dst=r2 src=r0 offset=0 imm=-4
#line 280 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1371 dst=r1 src=r0 offset=0 imm=0
#line 280 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=1373 dst=r0 src=r0 offset=0 imm=17
#line 280 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 280 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 280 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 280 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=1374 dst=r1 src=r0 offset=0 imm=0
#line 280 "sample/map.c"
    r1 = r0;
    // EBPF_OP_LSH64_IMM pc=1375 dst=r1 src=r0 offset=0 imm=32
#line 280 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1376 dst=r1 src=r0 offset=0 imm=32
#line 280 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=1377 dst=r1 src=r0 offset=1 imm=0
#line 280 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 280 "sample/map.c"
        goto label_50;
    // EBPF_OP_JA pc=1378 dst=r0 src=r0 offset=-86 imm=0
#line 280 "sample/map.c"
    goto label_43;
label_50:
    // EBPF_OP_LDXW pc=1379 dst=r1 src=r10 offset=-4 imm=0
#line 280 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=1380 dst=r1 src=r0 offset=86 imm=4
#line 280 "sample/map.c"
    if (r1 != IMMEDIATE(4))
#line 280 "sample/map.c"
        goto label_59;
    // EBPF_OP_MOV64_IMM pc=1381 dst=r1 src=r0 offset=0 imm=0
#line 280 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1382 dst=r10 src=r1 offset=-4 imm=0
#line 281 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1383 dst=r2 src=r10 offset=0 imm=0
#line 281 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1384 dst=r2 src=r0 offset=0 imm=-4
#line 281 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1385 dst=r1 src=r0 offset=0 imm=0
#line 281 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=1387 dst=r0 src=r0 offset=0 imm=17
#line 281 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 281 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 281 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 281 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=1388 dst=r1 src=r0 offset=0 imm=0
#line 281 "sample/map.c"
    r1 = r0;
    // EBPF_OP_LSH64_IMM pc=1389 dst=r1 src=r0 offset=0 imm=32
#line 281 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1390 dst=r1 src=r0 offset=0 imm=32
#line 281 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=1391 dst=r1 src=r0 offset=1 imm=0
#line 281 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 281 "sample/map.c"
        goto label_51;
    // EBPF_OP_JA pc=1392 dst=r0 src=r0 offset=-100 imm=0
#line 281 "sample/map.c"
    goto label_43;
label_51:
    // EBPF_OP_LDXW pc=1393 dst=r1 src=r10 offset=-4 imm=0
#line 281 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=1394 dst=r1 src=r0 offset=72 imm=3
#line 281 "sample/map.c"
    if (r1 != IMMEDIATE(3))
#line 281 "sample/map.c"
        goto label_59;
    // EBPF_OP_MOV64_IMM pc=1395 dst=r1 src=r0 offset=0 imm=0
#line 281 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1396 dst=r10 src=r1 offset=-4 imm=0
#line 282 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1397 dst=r2 src=r10 offset=0 imm=0
#line 282 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1398 dst=r2 src=r0 offset=0 imm=-4
#line 282 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1399 dst=r1 src=r0 offset=0 imm=0
#line 282 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=1401 dst=r0 src=r0 offset=0 imm=17
#line 282 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 282 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 282 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 282 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=1402 dst=r1 src=r0 offset=0 imm=0
#line 282 "sample/map.c"
    r1 = r0;
    // EBPF_OP_LSH64_IMM pc=1403 dst=r1 src=r0 offset=0 imm=32
#line 282 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1404 dst=r1 src=r0 offset=0 imm=32
#line 282 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=1405 dst=r1 src=r0 offset=1 imm=0
#line 282 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 282 "sample/map.c"
        goto label_52;
    // EBPF_OP_JA pc=1406 dst=r0 src=r0 offset=-114 imm=0
#line 282 "sample/map.c"
    goto label_43;
label_52:
    // EBPF_OP_LDXW pc=1407 dst=r1 src=r10 offset=-4 imm=0
#line 282 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=1408 dst=r1 src=r0 offset=58 imm=2
#line 282 "sample/map.c"
    if (r1 != IMMEDIATE(2))
#line 282 "sample/map.c"
        goto label_59;
    // EBPF_OP_MOV64_IMM pc=1409 dst=r1 src=r0 offset=0 imm=0
#line 282 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1410 dst=r10 src=r1 offset=-4 imm=0
#line 283 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1411 dst=r2 src=r10 offset=0 imm=0
#line 283 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1412 dst=r2 src=r0 offset=0 imm=-4
#line 283 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1413 dst=r1 src=r0 offset=0 imm=0
#line 283 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=1415 dst=r0 src=r0 offset=0 imm=17
#line 283 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 283 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 283 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 283 "sample/map.c"
        return 0;
    // EBPF_OP_MOV64_REG pc=1416 dst=r1 src=r0 offset=0 imm=0
#line 283 "sample/map.c"
    r1 = r0;
    // EBPF_OP_LSH64_IMM pc=1417 dst=r1 src=r0 offset=0 imm=32
#line 283 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1418 dst=r1 src=r0 offset=0 imm=32
#line 283 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=1419 dst=r1 src=r0 offset=1 imm=0
#line 283 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 283 "sample/map.c"
        goto label_53;
    // EBPF_OP_JA pc=1420 dst=r0 src=r0 offset=-128 imm=0
#line 283 "sample/map.c"
    goto label_43;
label_53:
    // EBPF_OP_LDXW pc=1421 dst=r1 src=r10 offset=-4 imm=0
#line 283 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=1422 dst=r1 src=r0 offset=44 imm=1
#line 283 "sample/map.c"
    if (r1 != IMMEDIATE(1))
#line 283 "sample/map.c"
        goto label_59;
    // EBPF_OP_MOV64_IMM pc=1423 dst=r1 src=r0 offset=0 imm=0
#line 283 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1424 dst=r10 src=r1 offset=-4 imm=0
#line 286 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1425 dst=r2 src=r10 offset=0 imm=0
#line 286 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1426 dst=r2 src=r0 offset=0 imm=-4
#line 286 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1427 dst=r1 src=r0 offset=0 imm=0
#line 286 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=1429 dst=r0 src=r0 offset=0 imm=18
#line 286 "sample/map.c"
    r0 = test_maps_helpers[4].address
#line 286 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 286 "sample/map.c"
    if ((test_maps_helpers[4].tail_call) && (r0 == 0))
#line 286 "sample/map.c"
        return 0;
    // EBPF_OP_LDXW pc=1430 dst=r1 src=r10 offset=-4 imm=0
#line 286 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=1431 dst=r7 src=r6 offset=0 imm=0
#line 286 "sample/map.c"
    r7 = r6;
    // EBPF_OP_JEQ_IMM pc=1432 dst=r1 src=r0 offset=1 imm=0
#line 286 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 286 "sample/map.c"
        goto label_54;
    // EBPF_OP_MOV64_IMM pc=1433 dst=r7 src=r0 offset=0 imm=-1
#line 286 "sample/map.c"
    r7 = IMMEDIATE(-1);
label_54:
    // EBPF_OP_MOV64_REG pc=1434 dst=r2 src=r0 offset=0 imm=0
#line 286 "sample/map.c"
    r2 = r0;
    // EBPF_OP_LSH64_IMM pc=1435 dst=r2 src=r0 offset=0 imm=32
#line 286 "sample/map.c"
    r2 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1436 dst=r2 src=r0 offset=0 imm=32
#line 286 "sample/map.c"
    r2 >>= IMMEDIATE(32);
    // EBPF_OP_LDDW pc=1437 dst=r3 src=r0 offset=0 imm=-7
#line 286 "sample/map.c"
    r3 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=1439 dst=r2 src=r3 offset=1 imm=0
#line 286 "sample/map.c"
    if (r2 == r3)
#line 286 "sample/map.c"
        goto label_55;
    // EBPF_OP_MOV64_REG pc=1440 dst=r7 src=r0 offset=0 imm=0
#line 286 "sample/map.c"
    r7 = r0;
label_55:
    // EBPF_OP_JNE_REG pc=1441 dst=r2 src=r3 offset=20 imm=0
#line 286 "sample/map.c"
    if (r2 != r3)
#line 286 "sample/map.c"
        goto label_58;
    // EBPF_OP_JNE_IMM pc=1442 dst=r1 src=r0 offset=19 imm=0
#line 286 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 286 "sample/map.c"
        goto label_58;
    // EBPF_OP_MOV64_IMM pc=1443 dst=r6 src=r0 offset=0 imm=0
#line 286 "sample/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1444 dst=r10 src=r6 offset=-4 imm=0
#line 287 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=1445 dst=r2 src=r10 offset=0 imm=0
#line 287 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1446 dst=r2 src=r0 offset=0 imm=-4
#line 287 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1447 dst=r1 src=r0 offset=0 imm=0
#line 287 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=1449 dst=r0 src=r0 offset=0 imm=17
#line 287 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 287 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 287 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 287 "sample/map.c"
        return 0;
    // EBPF_OP_LDXW pc=1450 dst=r1 src=r10 offset=-4 imm=0
#line 287 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1451 dst=r1 src=r0 offset=1 imm=0
#line 287 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 287 "sample/map.c"
        goto label_56;
    // EBPF_OP_MOV64_IMM pc=1452 dst=r7 src=r0 offset=0 imm=-1
#line 287 "sample/map.c"
    r7 = IMMEDIATE(-1);
label_56:
    // EBPF_OP_MOV64_REG pc=1453 dst=r2 src=r0 offset=0 imm=0
#line 287 "sample/map.c"
    r2 = r0;
    // EBPF_OP_LSH64_IMM pc=1454 dst=r2 src=r0 offset=0 imm=32
#line 287 "sample/map.c"
    r2 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1455 dst=r2 src=r0 offset=0 imm=32
#line 287 "sample/map.c"
    r2 >>= IMMEDIATE(32);
    // EBPF_OP_LDDW pc=1456 dst=r3 src=r0 offset=0 imm=-7
#line 287 "sample/map.c"
    r3 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=1458 dst=r2 src=r3 offset=1 imm=0
#line 287 "sample/map.c"
    if (r2 == r3)
#line 287 "sample/map.c"
        goto label_57;
    // EBPF_OP_MOV64_REG pc=1459 dst=r7 src=r0 offset=0 imm=0
#line 287 "sample/map.c"
    r7 = r0;
label_57:
    // EBPF_OP_JNE_REG pc=1460 dst=r2 src=r3 offset=1 imm=0
#line 287 "sample/map.c"
    if (r2 != r3)
#line 287 "sample/map.c"
        goto label_58;
    // EBPF_OP_JEQ_IMM pc=1461 dst=r1 src=r0 offset=-1416 imm=0
#line 287 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 287 "sample/map.c"
        goto label_1;
label_58:
    // EBPF_OP_MOV64_IMM pc=1462 dst=r6 src=r0 offset=0 imm=0
#line 287 "sample/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_MOV64_REG pc=1463 dst=r1 src=r7 offset=0 imm=0
#line 306 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=1464 dst=r1 src=r0 offset=0 imm=32
#line 306 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=1465 dst=r1 src=r0 offset=0 imm=32
#line 306 "sample/map.c"
    r1 = (int64_t)r1 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=1466 dst=r1 src=r0 offset=-1421 imm=-1
#line 306 "sample/map.c"
    if ((int64_t)r1 > IMMEDIATE(-1))
#line 306 "sample/map.c"
        goto label_1;
label_59:
    // EBPF_OP_MOV64_REG pc=1467 dst=r6 src=r7 offset=0 imm=0
#line 306 "sample/map.c"
    r6 = r7;
    // EBPF_OP_JA pc=1468 dst=r0 src=r0 offset=-1423 imm=0
#line 306 "sample/map.c"
    goto label_1;
#line 306 "sample/map.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        test_maps,
        "xdp_prog",
        "xdp_prog",
        "test_maps",
        test_maps_maps,
        8,
        test_maps_helpers,
        7,
        1469,
        &test_maps_program_type_guid,
        &test_maps_attach_type_guid,
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

metadata_table_t map_metadata_table = {sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version};
