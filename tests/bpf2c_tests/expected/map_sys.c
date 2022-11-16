// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from map.o

#include <guiddef.h>
#include <wdm.h>
#include <wsk.h>

#define NO_CRT
#include "bpf2c.h"

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

void
division_by_zero(uint32_t address)
{
    UNREFERENCED_PARAMETER(address);
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
    {NULL, 12, "helper_id_12"},
    {NULL, 3, "helper_id_3"},
    {NULL, 13, "helper_id_13"},
    {NULL, 4, "helper_id_4"},
    {NULL, 18, "helper_id_18"},
    {NULL, 14, "helper_id_14"},
    {NULL, 17, "helper_id_17"},
    {NULL, 16, "helper_id_16"},
    {NULL, 15, "helper_id_15"},
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
#line 189 "sample/map.c"
{
#line 189 "sample/map.c"
    // Prologue
#line 189 "sample/map.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 189 "sample/map.c"
    register uint64_t r0 = 0;
#line 189 "sample/map.c"
    register uint64_t r1 = 0;
#line 189 "sample/map.c"
    register uint64_t r2 = 0;
#line 189 "sample/map.c"
    register uint64_t r3 = 0;
#line 189 "sample/map.c"
    register uint64_t r4 = 0;
#line 189 "sample/map.c"
    register uint64_t r5 = 0;
#line 189 "sample/map.c"
    register uint64_t r6 = 0;
#line 189 "sample/map.c"
    register uint64_t r7 = 0;
#line 189 "sample/map.c"
    register uint64_t r8 = 0;
#line 189 "sample/map.c"
    register uint64_t r9 = 0;
#line 189 "sample/map.c"
    register uint64_t r10 = 0;

#line 189 "sample/map.c"
    r1 = (uintptr_t)context;
#line 189 "sample/map.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r1 src=r0 offset=0 imm=0
#line 189 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1 dst=r10 src=r1 offset=-4 imm=0
#line 66 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_IMM pc=2 dst=r1 src=r0 offset=0 imm=1
#line 66 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=3 dst=r10 src=r1 offset=-68 imm=0
#line 67 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-68)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=4 dst=r2 src=r10 offset=0 imm=0
#line 67 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=5 dst=r2 src=r0 offset=0 imm=-4
#line 67 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=6 dst=r3 src=r10 offset=0 imm=0
#line 67 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=7 dst=r3 src=r0 offset=0 imm=-68
#line 67 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=8 dst=r1 src=r0 offset=0 imm=0
#line 70 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=10 dst=r4 src=r0 offset=0 imm=0
#line 70 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=11 dst=r0 src=r0 offset=0 imm=2
#line 70 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 70 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 70 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 70 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=12 dst=r6 src=r0 offset=0 imm=0
#line 70 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=13 dst=r3 src=r6 offset=0 imm=0
#line 70 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=14 dst=r3 src=r0 offset=0 imm=32
#line 70 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=15 dst=r3 src=r0 offset=0 imm=32
#line 70 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=16 dst=r3 src=r0 offset=9 imm=-1
#line 71 "sample/map.c"
    if ((int64_t)r3 > (int64_t)IMMEDIATE(-1))
#line 71 "sample/map.c"
        goto label_2;
label_1:
    // EBPF_OP_LDDW pc=17 dst=r1 src=r0 offset=0 imm=1684369010
#line 71 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r1 offset=-40 imm=0
#line 71 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=20 dst=r1 src=r0 offset=0 imm=544040300
#line 71 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=22 dst=r10 src=r1 offset=-48 imm=0
#line 71 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=23 dst=r1 src=r0 offset=0 imm=1633972341
#line 71 "sample/map.c"
    r1 = (uint64_t)7304668671142817909;
    // EBPF_OP_JA pc=25 dst=r0 src=r0 offset=45 imm=0
#line 71 "sample/map.c"
    goto label_5;
label_2:
    // EBPF_OP_MOV64_REG pc=26 dst=r2 src=r10 offset=0 imm=0
#line 71 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=27 dst=r2 src=r0 offset=0 imm=-4
#line 71 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=28 dst=r1 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=30 dst=r0 src=r0 offset=0 imm=1
#line 76 "sample/map.c"
    r0 = test_maps_helpers[1].address
#line 76 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 76 "sample/map.c"
    if ((test_maps_helpers[1].tail_call) && (r0 == 0))
#line 76 "sample/map.c"
        return 0;
        // EBPF_OP_JNE_IMM pc=31 dst=r0 src=r0 offset=21 imm=0
#line 77 "sample/map.c"
    if (r0 != IMMEDIATE(0))
#line 77 "sample/map.c"
        goto label_4;
        // EBPF_OP_MOV64_IMM pc=32 dst=r1 src=r0 offset=0 imm=76
#line 77 "sample/map.c"
    r1 = IMMEDIATE(76);
    // EBPF_OP_STXH pc=33 dst=r10 src=r1 offset=-32 imm=0
#line 78 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=34 dst=r1 src=r0 offset=0 imm=1684369010
#line 78 "sample/map.c"
    r1 = (uint64_t)5500388420933217906;
    // EBPF_OP_STXDW pc=36 dst=r10 src=r1 offset=-40 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=37 dst=r1 src=r0 offset=0 imm=544040300
#line 78 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=39 dst=r10 src=r1 offset=-48 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=40 dst=r1 src=r0 offset=0 imm=1802465132
#line 78 "sample/map.c"
    r1 = (uint64_t)7304680770234183532;
    // EBPF_OP_STXDW pc=42 dst=r10 src=r1 offset=-56 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=43 dst=r1 src=r0 offset=0 imm=1600548962
#line 78 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=45 dst=r10 src=r1 offset=-64 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=46 dst=r1 src=r10 offset=0 imm=0
#line 78 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=47 dst=r1 src=r0 offset=0 imm=-64
#line 78 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=48 dst=r2 src=r0 offset=0 imm=34
#line 78 "sample/map.c"
    r2 = IMMEDIATE(34);
label_3:
    // EBPF_OP_CALL pc=49 dst=r0 src=r0 offset=0 imm=12
#line 78 "sample/map.c"
    r0 = test_maps_helpers[2].address
#line 78 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 78 "sample/map.c"
    if ((test_maps_helpers[2].tail_call) && (r0 == 0))
#line 78 "sample/map.c"
        return 0;
        // EBPF_OP_LDDW pc=50 dst=r6 src=r0 offset=0 imm=-1
#line 78 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JA pc=52 dst=r0 src=r0 offset=26 imm=0
#line 78 "sample/map.c"
    goto label_6;
label_4:
    // EBPF_OP_MOV64_REG pc=53 dst=r2 src=r10 offset=0 imm=0
#line 78 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=54 dst=r2 src=r0 offset=0 imm=-4
#line 78 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=55 dst=r1 src=r0 offset=0 imm=0
#line 82 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=57 dst=r0 src=r0 offset=0 imm=3
#line 82 "sample/map.c"
    r0 = test_maps_helpers[3].address
#line 82 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 82 "sample/map.c"
    if ((test_maps_helpers[3].tail_call) && (r0 == 0))
#line 82 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=58 dst=r6 src=r0 offset=0 imm=0
#line 82 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=59 dst=r3 src=r6 offset=0 imm=0
#line 82 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=60 dst=r3 src=r0 offset=0 imm=32
#line 82 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=61 dst=r3 src=r0 offset=0 imm=32
#line 82 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=62 dst=r3 src=r0 offset=41 imm=-1
#line 83 "sample/map.c"
    if ((int64_t)r3 > (int64_t)IMMEDIATE(-1))
#line 83 "sample/map.c"
        goto label_9;
        // EBPF_OP_LDDW pc=63 dst=r1 src=r0 offset=0 imm=1684369010
#line 83 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=65 dst=r10 src=r1 offset=-40 imm=0
#line 84 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=66 dst=r1 src=r0 offset=0 imm=544040300
#line 84 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=68 dst=r10 src=r1 offset=-48 imm=0
#line 84 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=69 dst=r1 src=r0 offset=0 imm=1701602660
#line 84 "sample/map.c"
    r1 = (uint64_t)7304668671210448228;
label_5:
    // EBPF_OP_STXDW pc=71 dst=r10 src=r1 offset=-56 imm=0
#line 84 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=72 dst=r1 src=r0 offset=0 imm=1600548962
#line 84 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=74 dst=r10 src=r1 offset=-64 imm=0
#line 84 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=75 dst=r1 src=r10 offset=0 imm=0
#line 84 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=76 dst=r1 src=r0 offset=0 imm=-64
#line 84 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=77 dst=r2 src=r0 offset=0 imm=32
#line 84 "sample/map.c"
    r2 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=78 dst=r0 src=r0 offset=0 imm=13
#line 84 "sample/map.c"
    r0 = test_maps_helpers[4].address
#line 84 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 84 "sample/map.c"
    if ((test_maps_helpers[4].tail_call) && (r0 == 0))
#line 84 "sample/map.c"
        return 0;
label_6:
    // EBPF_OP_MOV64_IMM pc=79 dst=r1 src=r0 offset=0 imm=100
#line 84 "sample/map.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXH pc=80 dst=r10 src=r1 offset=-28 imm=0
#line 192 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-28)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=81 dst=r1 src=r0 offset=0 imm=622879845
#line 192 "sample/map.c"
    r1 = IMMEDIATE(622879845);
    // EBPF_OP_STXW pc=82 dst=r10 src=r1 offset=-32 imm=0
#line 192 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=83 dst=r1 src=r0 offset=0 imm=1701978184
#line 192 "sample/map.c"
    r1 = (uint64_t)7958552634295722056;
    // EBPF_OP_STXDW pc=85 dst=r10 src=r1 offset=-40 imm=0
#line 192 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=86 dst=r1 src=r0 offset=0 imm=1885433120
#line 192 "sample/map.c"
    r1 = (uint64_t)5999155482795797792;
    // EBPF_OP_STXDW pc=88 dst=r10 src=r1 offset=-48 imm=0
#line 192 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=89 dst=r1 src=r0 offset=0 imm=1279349317
#line 192 "sample/map.c"
    r1 = (uint64_t)8245921731643003461;
    // EBPF_OP_STXDW pc=91 dst=r10 src=r1 offset=-56 imm=0
#line 192 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=92 dst=r1 src=r0 offset=0 imm=1953719636
#line 192 "sample/map.c"
    r1 = (uint64_t)5639992313069659476;
    // EBPF_OP_STXDW pc=94 dst=r10 src=r1 offset=-64 imm=0
#line 192 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=95 dst=r3 src=r6 offset=0 imm=0
#line 192 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=96 dst=r3 src=r0 offset=0 imm=32
#line 192 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=97 dst=r3 src=r0 offset=0 imm=32
#line 192 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=98 dst=r1 src=r10 offset=0 imm=0
#line 192 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=99 dst=r1 src=r0 offset=0 imm=-64
#line 192 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=100 dst=r2 src=r0 offset=0 imm=38
#line 192 "sample/map.c"
    r2 = IMMEDIATE(38);
label_7:
    // EBPF_OP_CALL pc=101 dst=r0 src=r0 offset=0 imm=13
#line 192 "sample/map.c"
    r0 = test_maps_helpers[4].address
#line 192 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 192 "sample/map.c"
    if ((test_maps_helpers[4].tail_call) && (r0 == 0))
#line 192 "sample/map.c"
        return 0;
label_8:
    // EBPF_OP_MOV64_REG pc=102 dst=r0 src=r6 offset=0 imm=0
#line 205 "sample/map.c"
    r0 = r6;
    // EBPF_OP_EXIT pc=103 dst=r0 src=r0 offset=0 imm=0
#line 205 "sample/map.c"
    return r0;
label_9:
    // EBPF_OP_MOV64_REG pc=104 dst=r2 src=r10 offset=0 imm=0
#line 205 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=105 dst=r2 src=r0 offset=0 imm=-4
#line 205 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=106 dst=r3 src=r10 offset=0 imm=0
#line 205 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=107 dst=r3 src=r0 offset=0 imm=-68
#line 205 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=108 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_MOV64_IMM pc=110 dst=r4 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=111 dst=r0 src=r0 offset=0 imm=2
#line 88 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 88 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 88 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 88 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=112 dst=r6 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=113 dst=r3 src=r6 offset=0 imm=0
#line 88 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=114 dst=r3 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=115 dst=r3 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=116 dst=r3 src=r0 offset=1 imm=-1
#line 89 "sample/map.c"
    if ((int64_t)r3 > (int64_t)IMMEDIATE(-1))
#line 89 "sample/map.c"
        goto label_10;
        // EBPF_OP_JA pc=117 dst=r0 src=r0 offset=-101 imm=0
#line 89 "sample/map.c"
    goto label_1;
label_10:
    // EBPF_OP_MOV64_REG pc=118 dst=r2 src=r10 offset=0 imm=0
#line 89 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=119 dst=r2 src=r0 offset=0 imm=-4
#line 89 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=120 dst=r1 src=r0 offset=0 imm=0
#line 99 "sample/map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=122 dst=r0 src=r0 offset=0 imm=4
#line 99 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 99 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 99 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 99 "sample/map.c"
        return 0;
        // EBPF_OP_JNE_IMM pc=123 dst=r0 src=r0 offset=23 imm=0
#line 100 "sample/map.c"
    if (r0 != IMMEDIATE(0))
#line 100 "sample/map.c"
        goto label_11;
        // EBPF_OP_MOV64_IMM pc=124 dst=r1 src=r0 offset=0 imm=0
#line 100 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=125 dst=r10 src=r1 offset=-20 imm=0
#line 101 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-20)) = (uint8_t)r1;
    // EBPF_OP_MOV64_IMM pc=126 dst=r1 src=r0 offset=0 imm=1280070990
#line 101 "sample/map.c"
    r1 = IMMEDIATE(1280070990);
    // EBPF_OP_STXW pc=127 dst=r10 src=r1 offset=-24 imm=0
#line 101 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=128 dst=r1 src=r0 offset=0 imm=1920300133
#line 101 "sample/map.c"
    r1 = (uint64_t)2334102031925867621;
    // EBPF_OP_STXDW pc=130 dst=r10 src=r1 offset=-32 imm=0
#line 101 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=131 dst=r1 src=r0 offset=0 imm=1818582885
#line 101 "sample/map.c"
    r1 = (uint64_t)8223693201956233061;
    // EBPF_OP_STXDW pc=133 dst=r10 src=r1 offset=-40 imm=0
#line 101 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=134 dst=r1 src=r0 offset=0 imm=1683973230
#line 101 "sample/map.c"
    r1 = (uint64_t)8387229063778886766;
    // EBPF_OP_STXDW pc=136 dst=r10 src=r1 offset=-48 imm=0
#line 101 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=137 dst=r1 src=r0 offset=0 imm=1802465132
#line 101 "sample/map.c"
    r1 = (uint64_t)7016450394082471788;
    // EBPF_OP_STXDW pc=139 dst=r10 src=r1 offset=-56 imm=0
#line 101 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=140 dst=r1 src=r0 offset=0 imm=1600548962
#line 101 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=142 dst=r10 src=r1 offset=-64 imm=0
#line 101 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=143 dst=r1 src=r10 offset=0 imm=0
#line 101 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=144 dst=r1 src=r0 offset=0 imm=-64
#line 101 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=145 dst=r2 src=r0 offset=0 imm=45
#line 101 "sample/map.c"
    r2 = IMMEDIATE(45);
    // EBPF_OP_JA pc=146 dst=r0 src=r0 offset=-98 imm=0
#line 101 "sample/map.c"
    goto label_3;
label_11:
    // EBPF_OP_MOV64_IMM pc=147 dst=r1 src=r0 offset=0 imm=0
#line 101 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=148 dst=r10 src=r1 offset=-4 imm=0
#line 66 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_IMM pc=149 dst=r1 src=r0 offset=0 imm=1
#line 66 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=150 dst=r10 src=r1 offset=-68 imm=0
#line 67 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-68)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=151 dst=r2 src=r10 offset=0 imm=0
#line 67 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=152 dst=r2 src=r0 offset=0 imm=-4
#line 67 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=153 dst=r3 src=r10 offset=0 imm=0
#line 67 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=154 dst=r3 src=r0 offset=0 imm=-68
#line 67 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=155 dst=r1 src=r0 offset=0 imm=0
#line 70 "sample/map.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_MOV64_IMM pc=157 dst=r4 src=r0 offset=0 imm=0
#line 70 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=158 dst=r0 src=r0 offset=0 imm=2
#line 70 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 70 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 70 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 70 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=159 dst=r6 src=r0 offset=0 imm=0
#line 70 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=160 dst=r3 src=r6 offset=0 imm=0
#line 70 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=161 dst=r3 src=r0 offset=0 imm=32
#line 70 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=162 dst=r3 src=r0 offset=0 imm=32
#line 70 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=163 dst=r3 src=r0 offset=9 imm=-1
#line 71 "sample/map.c"
    if ((int64_t)r3 > (int64_t)IMMEDIATE(-1))
#line 71 "sample/map.c"
        goto label_13;
label_12:
    // EBPF_OP_LDDW pc=164 dst=r1 src=r0 offset=0 imm=1684369010
#line 71 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=166 dst=r10 src=r1 offset=-40 imm=0
#line 71 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=167 dst=r1 src=r0 offset=0 imm=544040300
#line 71 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=169 dst=r10 src=r1 offset=-48 imm=0
#line 71 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=170 dst=r1 src=r0 offset=0 imm=1633972341
#line 71 "sample/map.c"
    r1 = (uint64_t)7304668671142817909;
    // EBPF_OP_JA pc=172 dst=r0 src=r0 offset=45 imm=0
#line 71 "sample/map.c"
    goto label_16;
label_13:
    // EBPF_OP_MOV64_REG pc=173 dst=r2 src=r10 offset=0 imm=0
#line 71 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=174 dst=r2 src=r0 offset=0 imm=-4
#line 71 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=175 dst=r1 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=177 dst=r0 src=r0 offset=0 imm=1
#line 76 "sample/map.c"
    r0 = test_maps_helpers[1].address
#line 76 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 76 "sample/map.c"
    if ((test_maps_helpers[1].tail_call) && (r0 == 0))
#line 76 "sample/map.c"
        return 0;
        // EBPF_OP_JNE_IMM pc=178 dst=r0 src=r0 offset=21 imm=0
#line 77 "sample/map.c"
    if (r0 != IMMEDIATE(0))
#line 77 "sample/map.c"
        goto label_15;
        // EBPF_OP_MOV64_IMM pc=179 dst=r1 src=r0 offset=0 imm=76
#line 77 "sample/map.c"
    r1 = IMMEDIATE(76);
    // EBPF_OP_STXH pc=180 dst=r10 src=r1 offset=-32 imm=0
#line 78 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=181 dst=r1 src=r0 offset=0 imm=1684369010
#line 78 "sample/map.c"
    r1 = (uint64_t)5500388420933217906;
    // EBPF_OP_STXDW pc=183 dst=r10 src=r1 offset=-40 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=184 dst=r1 src=r0 offset=0 imm=544040300
#line 78 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=186 dst=r10 src=r1 offset=-48 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=187 dst=r1 src=r0 offset=0 imm=1802465132
#line 78 "sample/map.c"
    r1 = (uint64_t)7304680770234183532;
    // EBPF_OP_STXDW pc=189 dst=r10 src=r1 offset=-56 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=190 dst=r1 src=r0 offset=0 imm=1600548962
#line 78 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=192 dst=r10 src=r1 offset=-64 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=193 dst=r1 src=r10 offset=0 imm=0
#line 78 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=194 dst=r1 src=r0 offset=0 imm=-64
#line 78 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=195 dst=r2 src=r0 offset=0 imm=34
#line 78 "sample/map.c"
    r2 = IMMEDIATE(34);
label_14:
    // EBPF_OP_CALL pc=196 dst=r0 src=r0 offset=0 imm=12
#line 78 "sample/map.c"
    r0 = test_maps_helpers[2].address
#line 78 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 78 "sample/map.c"
    if ((test_maps_helpers[2].tail_call) && (r0 == 0))
#line 78 "sample/map.c"
        return 0;
        // EBPF_OP_LDDW pc=197 dst=r6 src=r0 offset=0 imm=-1
#line 78 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JA pc=199 dst=r0 src=r0 offset=26 imm=0
#line 78 "sample/map.c"
    goto label_17;
label_15:
    // EBPF_OP_MOV64_REG pc=200 dst=r2 src=r10 offset=0 imm=0
#line 78 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=201 dst=r2 src=r0 offset=0 imm=-4
#line 78 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=202 dst=r1 src=r0 offset=0 imm=0
#line 82 "sample/map.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=204 dst=r0 src=r0 offset=0 imm=3
#line 82 "sample/map.c"
    r0 = test_maps_helpers[3].address
#line 82 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 82 "sample/map.c"
    if ((test_maps_helpers[3].tail_call) && (r0 == 0))
#line 82 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=205 dst=r6 src=r0 offset=0 imm=0
#line 82 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=206 dst=r3 src=r6 offset=0 imm=0
#line 82 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=207 dst=r3 src=r0 offset=0 imm=32
#line 82 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=208 dst=r3 src=r0 offset=0 imm=32
#line 82 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=209 dst=r3 src=r0 offset=42 imm=-1
#line 83 "sample/map.c"
    if ((int64_t)r3 > (int64_t)IMMEDIATE(-1))
#line 83 "sample/map.c"
        goto label_18;
        // EBPF_OP_LDDW pc=210 dst=r1 src=r0 offset=0 imm=1684369010
#line 83 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=212 dst=r10 src=r1 offset=-40 imm=0
#line 84 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=213 dst=r1 src=r0 offset=0 imm=544040300
#line 84 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=215 dst=r10 src=r1 offset=-48 imm=0
#line 84 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=216 dst=r1 src=r0 offset=0 imm=1701602660
#line 84 "sample/map.c"
    r1 = (uint64_t)7304668671210448228;
label_16:
    // EBPF_OP_STXDW pc=218 dst=r10 src=r1 offset=-56 imm=0
#line 84 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=219 dst=r1 src=r0 offset=0 imm=1600548962
#line 84 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=221 dst=r10 src=r1 offset=-64 imm=0
#line 84 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=222 dst=r1 src=r10 offset=0 imm=0
#line 84 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=223 dst=r1 src=r0 offset=0 imm=-64
#line 84 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=224 dst=r2 src=r0 offset=0 imm=32
#line 84 "sample/map.c"
    r2 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=225 dst=r0 src=r0 offset=0 imm=13
#line 84 "sample/map.c"
    r0 = test_maps_helpers[4].address
#line 84 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 84 "sample/map.c"
    if ((test_maps_helpers[4].tail_call) && (r0 == 0))
#line 84 "sample/map.c"
        return 0;
label_17:
    // EBPF_OP_MOV64_IMM pc=226 dst=r1 src=r0 offset=0 imm=0
#line 84 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=227 dst=r10 src=r1 offset=-20 imm=0
#line 193 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-20)) = (uint8_t)r1;
    // EBPF_OP_MOV64_IMM pc=228 dst=r1 src=r0 offset=0 imm=1680154724
#line 193 "sample/map.c"
    r1 = IMMEDIATE(1680154724);
    // EBPF_OP_STXW pc=229 dst=r10 src=r1 offset=-24 imm=0
#line 193 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=230 dst=r1 src=r0 offset=0 imm=1952805408
#line 193 "sample/map.c"
    r1 = (uint64_t)7308905094058439200;
    // EBPF_OP_STXDW pc=232 dst=r10 src=r1 offset=-32 imm=0
#line 193 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=233 dst=r1 src=r0 offset=0 imm=1599426627
#line 193 "sample/map.c"
    r1 = (uint64_t)5211580972890673219;
    // EBPF_OP_STXDW pc=235 dst=r10 src=r1 offset=-40 imm=0
#line 193 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=236 dst=r1 src=r0 offset=0 imm=1885433120
#line 193 "sample/map.c"
    r1 = (uint64_t)5928232584757734688;
    // EBPF_OP_STXDW pc=238 dst=r10 src=r1 offset=-48 imm=0
#line 193 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=239 dst=r1 src=r0 offset=0 imm=1279349317
#line 193 "sample/map.c"
    r1 = (uint64_t)8245921731643003461;
    // EBPF_OP_STXDW pc=241 dst=r10 src=r1 offset=-56 imm=0
#line 193 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=242 dst=r1 src=r0 offset=0 imm=1953719636
#line 193 "sample/map.c"
    r1 = (uint64_t)5639992313069659476;
    // EBPF_OP_STXDW pc=244 dst=r10 src=r1 offset=-64 imm=0
#line 193 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=245 dst=r3 src=r6 offset=0 imm=0
#line 193 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=246 dst=r3 src=r0 offset=0 imm=32
#line 193 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=247 dst=r3 src=r0 offset=0 imm=32
#line 193 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=248 dst=r1 src=r10 offset=0 imm=0
#line 193 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=249 dst=r1 src=r0 offset=0 imm=-64
#line 193 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=250 dst=r2 src=r0 offset=0 imm=45
#line 193 "sample/map.c"
    r2 = IMMEDIATE(45);
    // EBPF_OP_JA pc=251 dst=r0 src=r0 offset=-151 imm=0
#line 193 "sample/map.c"
    goto label_7;
label_18:
    // EBPF_OP_MOV64_REG pc=252 dst=r2 src=r10 offset=0 imm=0
#line 193 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=253 dst=r2 src=r0 offset=0 imm=-4
#line 193 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=254 dst=r3 src=r10 offset=0 imm=0
#line 193 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=255 dst=r3 src=r0 offset=0 imm=-68
#line 193 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=256 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_MOV64_IMM pc=258 dst=r4 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=259 dst=r0 src=r0 offset=0 imm=2
#line 88 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 88 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 88 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 88 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=260 dst=r6 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=261 dst=r3 src=r6 offset=0 imm=0
#line 88 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=262 dst=r3 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=263 dst=r3 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=264 dst=r3 src=r0 offset=1 imm=-1
#line 89 "sample/map.c"
    if ((int64_t)r3 > (int64_t)IMMEDIATE(-1))
#line 89 "sample/map.c"
        goto label_19;
        // EBPF_OP_JA pc=265 dst=r0 src=r0 offset=-102 imm=0
#line 89 "sample/map.c"
    goto label_12;
label_19:
    // EBPF_OP_MOV64_REG pc=266 dst=r2 src=r10 offset=0 imm=0
#line 89 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=267 dst=r2 src=r0 offset=0 imm=-4
#line 89 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=268 dst=r1 src=r0 offset=0 imm=0
#line 99 "sample/map.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=270 dst=r0 src=r0 offset=0 imm=4
#line 99 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 99 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 99 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 99 "sample/map.c"
        return 0;
        // EBPF_OP_JNE_IMM pc=271 dst=r0 src=r0 offset=23 imm=0
#line 100 "sample/map.c"
    if (r0 != IMMEDIATE(0))
#line 100 "sample/map.c"
        goto label_20;
        // EBPF_OP_MOV64_IMM pc=272 dst=r1 src=r0 offset=0 imm=0
#line 100 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=273 dst=r10 src=r1 offset=-20 imm=0
#line 101 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-20)) = (uint8_t)r1;
    // EBPF_OP_MOV64_IMM pc=274 dst=r1 src=r0 offset=0 imm=1280070990
#line 101 "sample/map.c"
    r1 = IMMEDIATE(1280070990);
    // EBPF_OP_STXW pc=275 dst=r10 src=r1 offset=-24 imm=0
#line 101 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=276 dst=r1 src=r0 offset=0 imm=1920300133
#line 101 "sample/map.c"
    r1 = (uint64_t)2334102031925867621;
    // EBPF_OP_STXDW pc=278 dst=r10 src=r1 offset=-32 imm=0
#line 101 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=279 dst=r1 src=r0 offset=0 imm=1818582885
#line 101 "sample/map.c"
    r1 = (uint64_t)8223693201956233061;
    // EBPF_OP_STXDW pc=281 dst=r10 src=r1 offset=-40 imm=0
#line 101 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=282 dst=r1 src=r0 offset=0 imm=1683973230
#line 101 "sample/map.c"
    r1 = (uint64_t)8387229063778886766;
    // EBPF_OP_STXDW pc=284 dst=r10 src=r1 offset=-48 imm=0
#line 101 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=285 dst=r1 src=r0 offset=0 imm=1802465132
#line 101 "sample/map.c"
    r1 = (uint64_t)7016450394082471788;
    // EBPF_OP_STXDW pc=287 dst=r10 src=r1 offset=-56 imm=0
#line 101 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=288 dst=r1 src=r0 offset=0 imm=1600548962
#line 101 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=290 dst=r10 src=r1 offset=-64 imm=0
#line 101 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=291 dst=r1 src=r10 offset=0 imm=0
#line 101 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=292 dst=r1 src=r0 offset=0 imm=-64
#line 101 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=293 dst=r2 src=r0 offset=0 imm=45
#line 101 "sample/map.c"
    r2 = IMMEDIATE(45);
    // EBPF_OP_JA pc=294 dst=r0 src=r0 offset=-99 imm=0
#line 101 "sample/map.c"
    goto label_14;
label_20:
    // EBPF_OP_MOV64_IMM pc=295 dst=r1 src=r0 offset=0 imm=0
#line 101 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=296 dst=r10 src=r1 offset=-4 imm=0
#line 66 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_IMM pc=297 dst=r1 src=r0 offset=0 imm=1
#line 66 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=298 dst=r10 src=r1 offset=-68 imm=0
#line 67 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-68)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=299 dst=r2 src=r10 offset=0 imm=0
#line 67 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=300 dst=r2 src=r0 offset=0 imm=-4
#line 67 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=301 dst=r3 src=r10 offset=0 imm=0
#line 67 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=302 dst=r3 src=r0 offset=0 imm=-68
#line 67 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=303 dst=r1 src=r0 offset=0 imm=0
#line 70 "sample/map.c"
    r1 = POINTER(_maps[2].address);
    // EBPF_OP_MOV64_IMM pc=305 dst=r4 src=r0 offset=0 imm=0
#line 70 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=306 dst=r0 src=r0 offset=0 imm=2
#line 70 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 70 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 70 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 70 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=307 dst=r6 src=r0 offset=0 imm=0
#line 70 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=308 dst=r3 src=r6 offset=0 imm=0
#line 70 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=309 dst=r3 src=r0 offset=0 imm=32
#line 70 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=310 dst=r3 src=r0 offset=0 imm=32
#line 70 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=311 dst=r3 src=r0 offset=1 imm=-1
#line 71 "sample/map.c"
    if ((int64_t)r3 > (int64_t)IMMEDIATE(-1))
#line 71 "sample/map.c"
        goto label_21;
        // EBPF_OP_JA pc=312 dst=r0 src=r0 offset=60 imm=0
#line 71 "sample/map.c"
    goto label_24;
label_21:
    // EBPF_OP_MOV64_REG pc=313 dst=r2 src=r10 offset=0 imm=0
#line 71 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=314 dst=r2 src=r0 offset=0 imm=-4
#line 71 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=315 dst=r1 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r1 = POINTER(_maps[2].address);
    // EBPF_OP_CALL pc=317 dst=r0 src=r0 offset=0 imm=1
#line 76 "sample/map.c"
    r0 = test_maps_helpers[1].address
#line 76 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 76 "sample/map.c"
    if ((test_maps_helpers[1].tail_call) && (r0 == 0))
#line 76 "sample/map.c"
        return 0;
        // EBPF_OP_JNE_IMM pc=318 dst=r0 src=r0 offset=21 imm=0
#line 77 "sample/map.c"
    if (r0 != IMMEDIATE(0))
#line 77 "sample/map.c"
        goto label_22;
        // EBPF_OP_MOV64_IMM pc=319 dst=r1 src=r0 offset=0 imm=76
#line 77 "sample/map.c"
    r1 = IMMEDIATE(76);
    // EBPF_OP_STXH pc=320 dst=r10 src=r1 offset=-32 imm=0
#line 78 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=321 dst=r1 src=r0 offset=0 imm=1684369010
#line 78 "sample/map.c"
    r1 = (uint64_t)5500388420933217906;
    // EBPF_OP_STXDW pc=323 dst=r10 src=r1 offset=-40 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=324 dst=r1 src=r0 offset=0 imm=544040300
#line 78 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=326 dst=r10 src=r1 offset=-48 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=327 dst=r1 src=r0 offset=0 imm=1802465132
#line 78 "sample/map.c"
    r1 = (uint64_t)7304680770234183532;
    // EBPF_OP_STXDW pc=329 dst=r10 src=r1 offset=-56 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=330 dst=r1 src=r0 offset=0 imm=1600548962
#line 78 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=332 dst=r10 src=r1 offset=-64 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=333 dst=r1 src=r10 offset=0 imm=0
#line 78 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=334 dst=r1 src=r0 offset=0 imm=-64
#line 78 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=335 dst=r2 src=r0 offset=0 imm=34
#line 78 "sample/map.c"
    r2 = IMMEDIATE(34);
    // EBPF_OP_CALL pc=336 dst=r0 src=r0 offset=0 imm=12
#line 78 "sample/map.c"
    r0 = test_maps_helpers[2].address
#line 78 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 78 "sample/map.c"
    if ((test_maps_helpers[2].tail_call) && (r0 == 0))
#line 78 "sample/map.c"
        return 0;
        // EBPF_OP_LDDW pc=337 dst=r6 src=r0 offset=0 imm=-1
#line 78 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JA pc=339 dst=r0 src=r0 offset=49 imm=0
#line 78 "sample/map.c"
    goto label_26;
label_22:
    // EBPF_OP_MOV64_REG pc=340 dst=r2 src=r10 offset=0 imm=0
#line 78 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=341 dst=r2 src=r0 offset=0 imm=-4
#line 78 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=342 dst=r1 src=r0 offset=0 imm=0
#line 82 "sample/map.c"
    r1 = POINTER(_maps[2].address);
    // EBPF_OP_CALL pc=344 dst=r0 src=r0 offset=0 imm=3
#line 82 "sample/map.c"
    r0 = test_maps_helpers[3].address
#line 82 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 82 "sample/map.c"
    if ((test_maps_helpers[3].tail_call) && (r0 == 0))
#line 82 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=345 dst=r6 src=r0 offset=0 imm=0
#line 82 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=346 dst=r3 src=r6 offset=0 imm=0
#line 82 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=347 dst=r3 src=r0 offset=0 imm=32
#line 82 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=348 dst=r3 src=r0 offset=0 imm=32
#line 82 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=349 dst=r3 src=r0 offset=9 imm=-1
#line 83 "sample/map.c"
    if ((int64_t)r3 > (int64_t)IMMEDIATE(-1))
#line 83 "sample/map.c"
        goto label_23;
        // EBPF_OP_LDDW pc=350 dst=r1 src=r0 offset=0 imm=1684369010
#line 83 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=352 dst=r10 src=r1 offset=-40 imm=0
#line 84 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=353 dst=r1 src=r0 offset=0 imm=544040300
#line 84 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=355 dst=r10 src=r1 offset=-48 imm=0
#line 84 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=356 dst=r1 src=r0 offset=0 imm=1701602660
#line 84 "sample/map.c"
    r1 = (uint64_t)7304668671210448228;
    // EBPF_OP_JA pc=358 dst=r0 src=r0 offset=22 imm=0
#line 84 "sample/map.c"
    goto label_25;
label_23:
    // EBPF_OP_MOV64_REG pc=359 dst=r2 src=r10 offset=0 imm=0
#line 84 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=360 dst=r2 src=r0 offset=0 imm=-4
#line 84 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=361 dst=r3 src=r10 offset=0 imm=0
#line 84 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=362 dst=r3 src=r0 offset=0 imm=-68
#line 84 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_MOV64_IMM pc=363 dst=r7 src=r0 offset=0 imm=0
#line 84 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=364 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r1 = POINTER(_maps[2].address);
    // EBPF_OP_MOV64_IMM pc=366 dst=r4 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=367 dst=r0 src=r0 offset=0 imm=2
#line 88 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 88 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 88 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 88 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=368 dst=r6 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=369 dst=r3 src=r6 offset=0 imm=0
#line 88 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=370 dst=r3 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=371 dst=r3 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=372 dst=r3 src=r0 offset=41 imm=-1
#line 89 "sample/map.c"
    if ((int64_t)r3 > (int64_t)IMMEDIATE(-1))
#line 89 "sample/map.c"
        goto label_27;
label_24:
    // EBPF_OP_LDDW pc=373 dst=r1 src=r0 offset=0 imm=1684369010
#line 89 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=375 dst=r10 src=r1 offset=-40 imm=0
#line 89 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=376 dst=r1 src=r0 offset=0 imm=544040300
#line 89 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=378 dst=r10 src=r1 offset=-48 imm=0
#line 89 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=379 dst=r1 src=r0 offset=0 imm=1633972341
#line 89 "sample/map.c"
    r1 = (uint64_t)7304668671142817909;
label_25:
    // EBPF_OP_STXDW pc=381 dst=r10 src=r1 offset=-56 imm=0
#line 89 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=382 dst=r1 src=r0 offset=0 imm=1600548962
#line 89 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=384 dst=r10 src=r1 offset=-64 imm=0
#line 89 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=385 dst=r1 src=r10 offset=0 imm=0
#line 89 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=386 dst=r1 src=r0 offset=0 imm=-64
#line 89 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=387 dst=r2 src=r0 offset=0 imm=32
#line 89 "sample/map.c"
    r2 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=388 dst=r0 src=r0 offset=0 imm=13
#line 89 "sample/map.c"
    r0 = test_maps_helpers[4].address
#line 89 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 89 "sample/map.c"
    if ((test_maps_helpers[4].tail_call) && (r0 == 0))
#line 89 "sample/map.c"
        return 0;
label_26:
    // EBPF_OP_MOV64_IMM pc=389 dst=r1 src=r0 offset=0 imm=0
#line 89 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=390 dst=r10 src=r1 offset=-26 imm=0
#line 194 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-26)) = (uint8_t)r1;
    // EBPF_OP_MOV64_IMM pc=391 dst=r1 src=r0 offset=0 imm=25637
#line 194 "sample/map.c"
    r1 = IMMEDIATE(25637);
    // EBPF_OP_STXH pc=392 dst=r10 src=r1 offset=-28 imm=0
#line 194 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-28)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=393 dst=r1 src=r0 offset=0 imm=543450478
#line 194 "sample/map.c"
    r1 = IMMEDIATE(543450478);
    // EBPF_OP_STXW pc=394 dst=r10 src=r1 offset=-32 imm=0
#line 194 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=395 dst=r1 src=r0 offset=0 imm=1914722625
#line 194 "sample/map.c"
    r1 = (uint64_t)8247626271654172993;
    // EBPF_OP_STXDW pc=397 dst=r10 src=r1 offset=-40 imm=0
#line 194 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=398 dst=r1 src=r0 offset=0 imm=1885433120
#line 194 "sample/map.c"
    r1 = (uint64_t)5931875266780556576;
    // EBPF_OP_STXDW pc=400 dst=r10 src=r1 offset=-48 imm=0
#line 194 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=401 dst=r1 src=r0 offset=0 imm=1279349317
#line 194 "sample/map.c"
    r1 = (uint64_t)8245921731643003461;
    // EBPF_OP_STXDW pc=403 dst=r10 src=r1 offset=-56 imm=0
#line 194 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=404 dst=r1 src=r0 offset=0 imm=1953719636
#line 194 "sample/map.c"
    r1 = (uint64_t)5639992313069659476;
    // EBPF_OP_STXDW pc=406 dst=r10 src=r1 offset=-64 imm=0
#line 194 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=407 dst=r3 src=r6 offset=0 imm=0
#line 194 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=408 dst=r3 src=r0 offset=0 imm=32
#line 194 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=409 dst=r3 src=r0 offset=0 imm=32
#line 194 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=410 dst=r1 src=r10 offset=0 imm=0
#line 194 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=411 dst=r1 src=r0 offset=0 imm=-64
#line 194 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=412 dst=r2 src=r0 offset=0 imm=39
#line 194 "sample/map.c"
    r2 = IMMEDIATE(39);
    // EBPF_OP_JA pc=413 dst=r0 src=r0 offset=-313 imm=0
#line 194 "sample/map.c"
    goto label_7;
label_27:
    // EBPF_OP_STXW pc=414 dst=r10 src=r7 offset=-4 imm=0
#line 66 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_IMM pc=415 dst=r1 src=r0 offset=0 imm=1
#line 66 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=416 dst=r10 src=r1 offset=-68 imm=0
#line 67 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-68)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=417 dst=r2 src=r10 offset=0 imm=0
#line 67 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=418 dst=r2 src=r0 offset=0 imm=-4
#line 67 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=419 dst=r3 src=r10 offset=0 imm=0
#line 67 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=420 dst=r3 src=r0 offset=0 imm=-68
#line 67 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=421 dst=r1 src=r0 offset=0 imm=0
#line 70 "sample/map.c"
    r1 = POINTER(_maps[3].address);
    // EBPF_OP_MOV64_IMM pc=423 dst=r4 src=r0 offset=0 imm=0
#line 70 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=424 dst=r0 src=r0 offset=0 imm=2
#line 70 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 70 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 70 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 70 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=425 dst=r6 src=r0 offset=0 imm=0
#line 70 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=426 dst=r3 src=r6 offset=0 imm=0
#line 70 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=427 dst=r3 src=r0 offset=0 imm=32
#line 70 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=428 dst=r3 src=r0 offset=0 imm=32
#line 70 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=429 dst=r3 src=r0 offset=1 imm=-1
#line 71 "sample/map.c"
    if ((int64_t)r3 > (int64_t)IMMEDIATE(-1))
#line 71 "sample/map.c"
        goto label_28;
        // EBPF_OP_JA pc=430 dst=r0 src=r0 offset=60 imm=0
#line 71 "sample/map.c"
    goto label_31;
label_28:
    // EBPF_OP_MOV64_REG pc=431 dst=r2 src=r10 offset=0 imm=0
#line 71 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=432 dst=r2 src=r0 offset=0 imm=-4
#line 71 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=433 dst=r1 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r1 = POINTER(_maps[3].address);
    // EBPF_OP_CALL pc=435 dst=r0 src=r0 offset=0 imm=1
#line 76 "sample/map.c"
    r0 = test_maps_helpers[1].address
#line 76 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 76 "sample/map.c"
    if ((test_maps_helpers[1].tail_call) && (r0 == 0))
#line 76 "sample/map.c"
        return 0;
        // EBPF_OP_JNE_IMM pc=436 dst=r0 src=r0 offset=21 imm=0
#line 77 "sample/map.c"
    if (r0 != IMMEDIATE(0))
#line 77 "sample/map.c"
        goto label_29;
        // EBPF_OP_MOV64_IMM pc=437 dst=r1 src=r0 offset=0 imm=76
#line 77 "sample/map.c"
    r1 = IMMEDIATE(76);
    // EBPF_OP_STXH pc=438 dst=r10 src=r1 offset=-32 imm=0
#line 78 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=439 dst=r1 src=r0 offset=0 imm=1684369010
#line 78 "sample/map.c"
    r1 = (uint64_t)5500388420933217906;
    // EBPF_OP_STXDW pc=441 dst=r10 src=r1 offset=-40 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=442 dst=r1 src=r0 offset=0 imm=544040300
#line 78 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=444 dst=r10 src=r1 offset=-48 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=445 dst=r1 src=r0 offset=0 imm=1802465132
#line 78 "sample/map.c"
    r1 = (uint64_t)7304680770234183532;
    // EBPF_OP_STXDW pc=447 dst=r10 src=r1 offset=-56 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=448 dst=r1 src=r0 offset=0 imm=1600548962
#line 78 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=450 dst=r10 src=r1 offset=-64 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=451 dst=r1 src=r10 offset=0 imm=0
#line 78 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=452 dst=r1 src=r0 offset=0 imm=-64
#line 78 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=453 dst=r2 src=r0 offset=0 imm=34
#line 78 "sample/map.c"
    r2 = IMMEDIATE(34);
    // EBPF_OP_CALL pc=454 dst=r0 src=r0 offset=0 imm=12
#line 78 "sample/map.c"
    r0 = test_maps_helpers[2].address
#line 78 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 78 "sample/map.c"
    if ((test_maps_helpers[2].tail_call) && (r0 == 0))
#line 78 "sample/map.c"
        return 0;
        // EBPF_OP_LDDW pc=455 dst=r6 src=r0 offset=0 imm=-1
#line 78 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JA pc=457 dst=r0 src=r0 offset=49 imm=0
#line 78 "sample/map.c"
    goto label_33;
label_29:
    // EBPF_OP_MOV64_REG pc=458 dst=r2 src=r10 offset=0 imm=0
#line 78 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=459 dst=r2 src=r0 offset=0 imm=-4
#line 78 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=460 dst=r1 src=r0 offset=0 imm=0
#line 82 "sample/map.c"
    r1 = POINTER(_maps[3].address);
    // EBPF_OP_CALL pc=462 dst=r0 src=r0 offset=0 imm=3
#line 82 "sample/map.c"
    r0 = test_maps_helpers[3].address
#line 82 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 82 "sample/map.c"
    if ((test_maps_helpers[3].tail_call) && (r0 == 0))
#line 82 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=463 dst=r6 src=r0 offset=0 imm=0
#line 82 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=464 dst=r3 src=r6 offset=0 imm=0
#line 82 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=465 dst=r3 src=r0 offset=0 imm=32
#line 82 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=466 dst=r3 src=r0 offset=0 imm=32
#line 82 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=467 dst=r3 src=r0 offset=9 imm=-1
#line 83 "sample/map.c"
    if ((int64_t)r3 > (int64_t)IMMEDIATE(-1))
#line 83 "sample/map.c"
        goto label_30;
        // EBPF_OP_LDDW pc=468 dst=r1 src=r0 offset=0 imm=1684369010
#line 83 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=470 dst=r10 src=r1 offset=-40 imm=0
#line 84 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=471 dst=r1 src=r0 offset=0 imm=544040300
#line 84 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=473 dst=r10 src=r1 offset=-48 imm=0
#line 84 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=474 dst=r1 src=r0 offset=0 imm=1701602660
#line 84 "sample/map.c"
    r1 = (uint64_t)7304668671210448228;
    // EBPF_OP_JA pc=476 dst=r0 src=r0 offset=22 imm=0
#line 84 "sample/map.c"
    goto label_32;
label_30:
    // EBPF_OP_MOV64_REG pc=477 dst=r2 src=r10 offset=0 imm=0
#line 84 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=478 dst=r2 src=r0 offset=0 imm=-4
#line 84 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=479 dst=r3 src=r10 offset=0 imm=0
#line 84 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=480 dst=r3 src=r0 offset=0 imm=-68
#line 84 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_MOV64_IMM pc=481 dst=r7 src=r0 offset=0 imm=0
#line 84 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=482 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r1 = POINTER(_maps[3].address);
    // EBPF_OP_MOV64_IMM pc=484 dst=r4 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=485 dst=r0 src=r0 offset=0 imm=2
#line 88 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 88 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 88 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 88 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=486 dst=r6 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=487 dst=r3 src=r6 offset=0 imm=0
#line 88 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=488 dst=r3 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=489 dst=r3 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=490 dst=r3 src=r0 offset=42 imm=-1
#line 89 "sample/map.c"
    if ((int64_t)r3 > (int64_t)IMMEDIATE(-1))
#line 89 "sample/map.c"
        goto label_34;
label_31:
    // EBPF_OP_LDDW pc=491 dst=r1 src=r0 offset=0 imm=1684369010
#line 89 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=493 dst=r10 src=r1 offset=-40 imm=0
#line 89 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=494 dst=r1 src=r0 offset=0 imm=544040300
#line 89 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=496 dst=r10 src=r1 offset=-48 imm=0
#line 89 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=497 dst=r1 src=r0 offset=0 imm=1633972341
#line 89 "sample/map.c"
    r1 = (uint64_t)7304668671142817909;
label_32:
    // EBPF_OP_STXDW pc=499 dst=r10 src=r1 offset=-56 imm=0
#line 89 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=500 dst=r1 src=r0 offset=0 imm=1600548962
#line 89 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=502 dst=r10 src=r1 offset=-64 imm=0
#line 89 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=503 dst=r1 src=r10 offset=0 imm=0
#line 89 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=504 dst=r1 src=r0 offset=0 imm=-64
#line 89 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=505 dst=r2 src=r0 offset=0 imm=32
#line 89 "sample/map.c"
    r2 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=506 dst=r0 src=r0 offset=0 imm=13
#line 89 "sample/map.c"
    r0 = test_maps_helpers[4].address
#line 89 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 89 "sample/map.c"
    if ((test_maps_helpers[4].tail_call) && (r0 == 0))
#line 89 "sample/map.c"
        return 0;
label_33:
    // EBPF_OP_MOV64_IMM pc=507 dst=r1 src=r0 offset=0 imm=100
#line 89 "sample/map.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXH pc=508 dst=r10 src=r1 offset=-20 imm=0
#line 195 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-20)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=509 dst=r1 src=r0 offset=0 imm=622879845
#line 195 "sample/map.c"
    r1 = IMMEDIATE(622879845);
    // EBPF_OP_STXW pc=510 dst=r10 src=r1 offset=-24 imm=0
#line 195 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=511 dst=r1 src=r0 offset=0 imm=1701978201
#line 195 "sample/map.c"
    r1 = (uint64_t)7958552634295722073;
    // EBPF_OP_STXDW pc=513 dst=r10 src=r1 offset=-32 imm=0
#line 195 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=514 dst=r1 src=r0 offset=0 imm=1599426627
#line 195 "sample/map.c"
    r1 = (uint64_t)4706915001281368131;
    // EBPF_OP_STXDW pc=516 dst=r10 src=r1 offset=-40 imm=0
#line 195 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=517 dst=r1 src=r0 offset=0 imm=1885433120
#line 195 "sample/map.c"
    r1 = (uint64_t)5928232584757734688;
    // EBPF_OP_STXDW pc=519 dst=r10 src=r1 offset=-48 imm=0
#line 195 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=520 dst=r1 src=r0 offset=0 imm=1279349317
#line 195 "sample/map.c"
    r1 = (uint64_t)8245921731643003461;
    // EBPF_OP_STXDW pc=522 dst=r10 src=r1 offset=-56 imm=0
#line 195 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=523 dst=r1 src=r0 offset=0 imm=1953719636
#line 195 "sample/map.c"
    r1 = (uint64_t)5639992313069659476;
    // EBPF_OP_STXDW pc=525 dst=r10 src=r1 offset=-64 imm=0
#line 195 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=526 dst=r3 src=r6 offset=0 imm=0
#line 195 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=527 dst=r3 src=r0 offset=0 imm=32
#line 195 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=528 dst=r3 src=r0 offset=0 imm=32
#line 195 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=529 dst=r1 src=r10 offset=0 imm=0
#line 195 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=530 dst=r1 src=r0 offset=0 imm=-64
#line 195 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=531 dst=r2 src=r0 offset=0 imm=46
#line 195 "sample/map.c"
    r2 = IMMEDIATE(46);
    // EBPF_OP_JA pc=532 dst=r0 src=r0 offset=-432 imm=0
#line 195 "sample/map.c"
    goto label_7;
label_34:
    // EBPF_OP_STXW pc=533 dst=r10 src=r7 offset=-4 imm=0
#line 66 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_IMM pc=534 dst=r1 src=r0 offset=0 imm=1
#line 66 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=535 dst=r10 src=r1 offset=-68 imm=0
#line 67 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-68)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=536 dst=r2 src=r10 offset=0 imm=0
#line 67 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=537 dst=r2 src=r0 offset=0 imm=-4
#line 67 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=538 dst=r3 src=r10 offset=0 imm=0
#line 67 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=539 dst=r3 src=r0 offset=0 imm=-68
#line 67 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=540 dst=r1 src=r0 offset=0 imm=0
#line 70 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_MOV64_IMM pc=542 dst=r4 src=r0 offset=0 imm=0
#line 70 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=543 dst=r0 src=r0 offset=0 imm=2
#line 70 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 70 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 70 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 70 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=544 dst=r6 src=r0 offset=0 imm=0
#line 70 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=545 dst=r3 src=r6 offset=0 imm=0
#line 70 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=546 dst=r3 src=r0 offset=0 imm=32
#line 70 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=547 dst=r3 src=r0 offset=0 imm=32
#line 70 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=548 dst=r3 src=r0 offset=9 imm=-1
#line 71 "sample/map.c"
    if ((int64_t)r3 > (int64_t)IMMEDIATE(-1))
#line 71 "sample/map.c"
        goto label_36;
label_35:
    // EBPF_OP_LDDW pc=549 dst=r1 src=r0 offset=0 imm=1684369010
#line 71 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=551 dst=r10 src=r1 offset=-40 imm=0
#line 71 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=552 dst=r1 src=r0 offset=0 imm=544040300
#line 71 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=554 dst=r10 src=r1 offset=-48 imm=0
#line 71 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=555 dst=r1 src=r0 offset=0 imm=1633972341
#line 71 "sample/map.c"
    r1 = (uint64_t)7304668671142817909;
    // EBPF_OP_JA pc=557 dst=r0 src=r0 offset=45 imm=0
#line 71 "sample/map.c"
    goto label_39;
label_36:
    // EBPF_OP_MOV64_REG pc=558 dst=r2 src=r10 offset=0 imm=0
#line 71 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=559 dst=r2 src=r0 offset=0 imm=-4
#line 71 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=560 dst=r1 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_CALL pc=562 dst=r0 src=r0 offset=0 imm=1
#line 76 "sample/map.c"
    r0 = test_maps_helpers[1].address
#line 76 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 76 "sample/map.c"
    if ((test_maps_helpers[1].tail_call) && (r0 == 0))
#line 76 "sample/map.c"
        return 0;
        // EBPF_OP_JNE_IMM pc=563 dst=r0 src=r0 offset=21 imm=0
#line 77 "sample/map.c"
    if (r0 != IMMEDIATE(0))
#line 77 "sample/map.c"
        goto label_38;
        // EBPF_OP_MOV64_IMM pc=564 dst=r1 src=r0 offset=0 imm=76
#line 77 "sample/map.c"
    r1 = IMMEDIATE(76);
    // EBPF_OP_STXH pc=565 dst=r10 src=r1 offset=-32 imm=0
#line 78 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=566 dst=r1 src=r0 offset=0 imm=1684369010
#line 78 "sample/map.c"
    r1 = (uint64_t)5500388420933217906;
    // EBPF_OP_STXDW pc=568 dst=r10 src=r1 offset=-40 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=569 dst=r1 src=r0 offset=0 imm=544040300
#line 78 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=571 dst=r10 src=r1 offset=-48 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=572 dst=r1 src=r0 offset=0 imm=1802465132
#line 78 "sample/map.c"
    r1 = (uint64_t)7304680770234183532;
    // EBPF_OP_STXDW pc=574 dst=r10 src=r1 offset=-56 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=575 dst=r1 src=r0 offset=0 imm=1600548962
#line 78 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=577 dst=r10 src=r1 offset=-64 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=578 dst=r1 src=r10 offset=0 imm=0
#line 78 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=579 dst=r1 src=r0 offset=0 imm=-64
#line 78 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=580 dst=r2 src=r0 offset=0 imm=34
#line 78 "sample/map.c"
    r2 = IMMEDIATE(34);
label_37:
    // EBPF_OP_CALL pc=581 dst=r0 src=r0 offset=0 imm=12
#line 78 "sample/map.c"
    r0 = test_maps_helpers[2].address
#line 78 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 78 "sample/map.c"
    if ((test_maps_helpers[2].tail_call) && (r0 == 0))
#line 78 "sample/map.c"
        return 0;
        // EBPF_OP_LDDW pc=582 dst=r6 src=r0 offset=0 imm=-1
#line 78 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JA pc=584 dst=r0 src=r0 offset=26 imm=0
#line 78 "sample/map.c"
    goto label_40;
label_38:
    // EBPF_OP_MOV64_REG pc=585 dst=r2 src=r10 offset=0 imm=0
#line 78 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=586 dst=r2 src=r0 offset=0 imm=-4
#line 78 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=587 dst=r1 src=r0 offset=0 imm=0
#line 82 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_CALL pc=589 dst=r0 src=r0 offset=0 imm=3
#line 82 "sample/map.c"
    r0 = test_maps_helpers[3].address
#line 82 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 82 "sample/map.c"
    if ((test_maps_helpers[3].tail_call) && (r0 == 0))
#line 82 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=590 dst=r6 src=r0 offset=0 imm=0
#line 82 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=591 dst=r3 src=r6 offset=0 imm=0
#line 82 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=592 dst=r3 src=r0 offset=0 imm=32
#line 82 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=593 dst=r3 src=r0 offset=0 imm=32
#line 82 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=594 dst=r3 src=r0 offset=40 imm=-1
#line 83 "sample/map.c"
    if ((int64_t)r3 > (int64_t)IMMEDIATE(-1))
#line 83 "sample/map.c"
        goto label_41;
        // EBPF_OP_LDDW pc=595 dst=r1 src=r0 offset=0 imm=1684369010
#line 83 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=597 dst=r10 src=r1 offset=-40 imm=0
#line 84 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=598 dst=r1 src=r0 offset=0 imm=544040300
#line 84 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=600 dst=r10 src=r1 offset=-48 imm=0
#line 84 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=601 dst=r1 src=r0 offset=0 imm=1701602660
#line 84 "sample/map.c"
    r1 = (uint64_t)7304668671210448228;
label_39:
    // EBPF_OP_STXDW pc=603 dst=r10 src=r1 offset=-56 imm=0
#line 84 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=604 dst=r1 src=r0 offset=0 imm=1600548962
#line 84 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=606 dst=r10 src=r1 offset=-64 imm=0
#line 84 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=607 dst=r1 src=r10 offset=0 imm=0
#line 84 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=608 dst=r1 src=r0 offset=0 imm=-64
#line 84 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=609 dst=r2 src=r0 offset=0 imm=32
#line 84 "sample/map.c"
    r2 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=610 dst=r0 src=r0 offset=0 imm=13
#line 84 "sample/map.c"
    r0 = test_maps_helpers[4].address
#line 84 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 84 "sample/map.c"
    if ((test_maps_helpers[4].tail_call) && (r0 == 0))
#line 84 "sample/map.c"
        return 0;
label_40:
    // EBPF_OP_MOV64_IMM pc=611 dst=r1 src=r0 offset=0 imm=100
#line 84 "sample/map.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXH pc=612 dst=r10 src=r1 offset=-24 imm=0
#line 196 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=613 dst=r1 src=r0 offset=0 imm=1852994932
#line 196 "sample/map.c"
    r1 = (uint64_t)2675248565465544052;
    // EBPF_OP_STXDW pc=615 dst=r10 src=r1 offset=-32 imm=0
#line 196 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=616 dst=r1 src=r0 offset=0 imm=1396787295
#line 196 "sample/map.c"
    r1 = (uint64_t)7309940640182257759;
    // EBPF_OP_STXDW pc=618 dst=r10 src=r1 offset=-40 imm=0
#line 196 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=619 dst=r1 src=r0 offset=0 imm=1885433120
#line 196 "sample/map.c"
    r1 = (uint64_t)6148060143522245920;
    // EBPF_OP_STXDW pc=621 dst=r10 src=r1 offset=-48 imm=0
#line 196 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=622 dst=r1 src=r0 offset=0 imm=1279349317
#line 196 "sample/map.c"
    r1 = (uint64_t)8245921731643003461;
    // EBPF_OP_STXDW pc=624 dst=r10 src=r1 offset=-56 imm=0
#line 196 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=625 dst=r1 src=r0 offset=0 imm=1953719636
#line 196 "sample/map.c"
    r1 = (uint64_t)5639992313069659476;
    // EBPF_OP_STXDW pc=627 dst=r10 src=r1 offset=-64 imm=0
#line 196 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=628 dst=r3 src=r6 offset=0 imm=0
#line 196 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=629 dst=r3 src=r0 offset=0 imm=32
#line 196 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=630 dst=r3 src=r0 offset=0 imm=32
#line 196 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=631 dst=r1 src=r10 offset=0 imm=0
#line 196 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=632 dst=r1 src=r0 offset=0 imm=-64
#line 196 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=633 dst=r2 src=r0 offset=0 imm=42
#line 196 "sample/map.c"
    r2 = IMMEDIATE(42);
    // EBPF_OP_JA pc=634 dst=r0 src=r0 offset=-534 imm=0
#line 196 "sample/map.c"
    goto label_7;
label_41:
    // EBPF_OP_MOV64_REG pc=635 dst=r2 src=r10 offset=0 imm=0
#line 196 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=636 dst=r2 src=r0 offset=0 imm=-4
#line 196 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=637 dst=r3 src=r10 offset=0 imm=0
#line 196 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=638 dst=r3 src=r0 offset=0 imm=-68
#line 196 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=639 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_MOV64_IMM pc=641 dst=r4 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=642 dst=r0 src=r0 offset=0 imm=2
#line 88 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 88 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 88 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 88 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=643 dst=r6 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=644 dst=r3 src=r6 offset=0 imm=0
#line 88 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=645 dst=r3 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=646 dst=r3 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=647 dst=r3 src=r0 offset=1 imm=-1
#line 89 "sample/map.c"
    if ((int64_t)r3 > (int64_t)IMMEDIATE(-1))
#line 89 "sample/map.c"
        goto label_42;
        // EBPF_OP_JA pc=648 dst=r0 src=r0 offset=-100 imm=0
#line 89 "sample/map.c"
    goto label_35;
label_42:
    // EBPF_OP_MOV64_REG pc=649 dst=r2 src=r10 offset=0 imm=0
#line 89 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=650 dst=r2 src=r0 offset=0 imm=-4
#line 89 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=651 dst=r1 src=r0 offset=0 imm=0
#line 99 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_CALL pc=653 dst=r0 src=r0 offset=0 imm=4
#line 99 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 99 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 99 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 99 "sample/map.c"
        return 0;
        // EBPF_OP_JNE_IMM pc=654 dst=r0 src=r0 offset=23 imm=0
#line 100 "sample/map.c"
    if (r0 != IMMEDIATE(0))
#line 100 "sample/map.c"
        goto label_43;
        // EBPF_OP_MOV64_IMM pc=655 dst=r1 src=r0 offset=0 imm=0
#line 100 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=656 dst=r10 src=r1 offset=-20 imm=0
#line 101 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-20)) = (uint8_t)r1;
    // EBPF_OP_MOV64_IMM pc=657 dst=r1 src=r0 offset=0 imm=1280070990
#line 101 "sample/map.c"
    r1 = IMMEDIATE(1280070990);
    // EBPF_OP_STXW pc=658 dst=r10 src=r1 offset=-24 imm=0
#line 101 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=659 dst=r1 src=r0 offset=0 imm=1920300133
#line 101 "sample/map.c"
    r1 = (uint64_t)2334102031925867621;
    // EBPF_OP_STXDW pc=661 dst=r10 src=r1 offset=-32 imm=0
#line 101 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=662 dst=r1 src=r0 offset=0 imm=1818582885
#line 101 "sample/map.c"
    r1 = (uint64_t)8223693201956233061;
    // EBPF_OP_STXDW pc=664 dst=r10 src=r1 offset=-40 imm=0
#line 101 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=665 dst=r1 src=r0 offset=0 imm=1683973230
#line 101 "sample/map.c"
    r1 = (uint64_t)8387229063778886766;
    // EBPF_OP_STXDW pc=667 dst=r10 src=r1 offset=-48 imm=0
#line 101 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=668 dst=r1 src=r0 offset=0 imm=1802465132
#line 101 "sample/map.c"
    r1 = (uint64_t)7016450394082471788;
    // EBPF_OP_STXDW pc=670 dst=r10 src=r1 offset=-56 imm=0
#line 101 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=671 dst=r1 src=r0 offset=0 imm=1600548962
#line 101 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=673 dst=r10 src=r1 offset=-64 imm=0
#line 101 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=674 dst=r1 src=r10 offset=0 imm=0
#line 101 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=675 dst=r1 src=r0 offset=0 imm=-64
#line 101 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=676 dst=r2 src=r0 offset=0 imm=45
#line 101 "sample/map.c"
    r2 = IMMEDIATE(45);
    // EBPF_OP_JA pc=677 dst=r0 src=r0 offset=-97 imm=0
#line 101 "sample/map.c"
    goto label_37;
label_43:
    // EBPF_OP_MOV64_IMM pc=678 dst=r1 src=r0 offset=0 imm=0
#line 101 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=679 dst=r10 src=r1 offset=-4 imm=0
#line 66 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_IMM pc=680 dst=r1 src=r0 offset=0 imm=1
#line 66 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=681 dst=r10 src=r1 offset=-68 imm=0
#line 67 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-68)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=682 dst=r2 src=r10 offset=0 imm=0
#line 67 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=683 dst=r2 src=r0 offset=0 imm=-4
#line 67 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=684 dst=r3 src=r10 offset=0 imm=0
#line 67 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=685 dst=r3 src=r0 offset=0 imm=-68
#line 67 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=686 dst=r1 src=r0 offset=0 imm=0
#line 70 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_MOV64_IMM pc=688 dst=r4 src=r0 offset=0 imm=0
#line 70 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=689 dst=r0 src=r0 offset=0 imm=2
#line 70 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 70 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 70 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 70 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=690 dst=r6 src=r0 offset=0 imm=0
#line 70 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=691 dst=r3 src=r6 offset=0 imm=0
#line 70 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=692 dst=r3 src=r0 offset=0 imm=32
#line 70 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=693 dst=r3 src=r0 offset=0 imm=32
#line 70 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=694 dst=r3 src=r0 offset=9 imm=-1
#line 71 "sample/map.c"
    if ((int64_t)r3 > (int64_t)IMMEDIATE(-1))
#line 71 "sample/map.c"
        goto label_45;
label_44:
    // EBPF_OP_LDDW pc=695 dst=r1 src=r0 offset=0 imm=1684369010
#line 71 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=697 dst=r10 src=r1 offset=-40 imm=0
#line 71 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=698 dst=r1 src=r0 offset=0 imm=544040300
#line 71 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=700 dst=r10 src=r1 offset=-48 imm=0
#line 71 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=701 dst=r1 src=r0 offset=0 imm=1633972341
#line 71 "sample/map.c"
    r1 = (uint64_t)7304668671142817909;
    // EBPF_OP_JA pc=703 dst=r0 src=r0 offset=45 imm=0
#line 71 "sample/map.c"
    goto label_48;
label_45:
    // EBPF_OP_MOV64_REG pc=704 dst=r2 src=r10 offset=0 imm=0
#line 71 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=705 dst=r2 src=r0 offset=0 imm=-4
#line 71 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=706 dst=r1 src=r0 offset=0 imm=0
#line 76 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_CALL pc=708 dst=r0 src=r0 offset=0 imm=1
#line 76 "sample/map.c"
    r0 = test_maps_helpers[1].address
#line 76 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 76 "sample/map.c"
    if ((test_maps_helpers[1].tail_call) && (r0 == 0))
#line 76 "sample/map.c"
        return 0;
        // EBPF_OP_JNE_IMM pc=709 dst=r0 src=r0 offset=21 imm=0
#line 77 "sample/map.c"
    if (r0 != IMMEDIATE(0))
#line 77 "sample/map.c"
        goto label_47;
        // EBPF_OP_MOV64_IMM pc=710 dst=r1 src=r0 offset=0 imm=76
#line 77 "sample/map.c"
    r1 = IMMEDIATE(76);
    // EBPF_OP_STXH pc=711 dst=r10 src=r1 offset=-32 imm=0
#line 78 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=712 dst=r1 src=r0 offset=0 imm=1684369010
#line 78 "sample/map.c"
    r1 = (uint64_t)5500388420933217906;
    // EBPF_OP_STXDW pc=714 dst=r10 src=r1 offset=-40 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=715 dst=r1 src=r0 offset=0 imm=544040300
#line 78 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=717 dst=r10 src=r1 offset=-48 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=718 dst=r1 src=r0 offset=0 imm=1802465132
#line 78 "sample/map.c"
    r1 = (uint64_t)7304680770234183532;
    // EBPF_OP_STXDW pc=720 dst=r10 src=r1 offset=-56 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=721 dst=r1 src=r0 offset=0 imm=1600548962
#line 78 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=723 dst=r10 src=r1 offset=-64 imm=0
#line 78 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=724 dst=r1 src=r10 offset=0 imm=0
#line 78 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=725 dst=r1 src=r0 offset=0 imm=-64
#line 78 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=726 dst=r2 src=r0 offset=0 imm=34
#line 78 "sample/map.c"
    r2 = IMMEDIATE(34);
label_46:
    // EBPF_OP_CALL pc=727 dst=r0 src=r0 offset=0 imm=12
#line 78 "sample/map.c"
    r0 = test_maps_helpers[2].address
#line 78 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 78 "sample/map.c"
    if ((test_maps_helpers[2].tail_call) && (r0 == 0))
#line 78 "sample/map.c"
        return 0;
        // EBPF_OP_LDDW pc=728 dst=r6 src=r0 offset=0 imm=-1
#line 78 "sample/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JA pc=730 dst=r0 src=r0 offset=26 imm=0
#line 78 "sample/map.c"
    goto label_49;
label_47:
    // EBPF_OP_MOV64_REG pc=731 dst=r2 src=r10 offset=0 imm=0
#line 78 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=732 dst=r2 src=r0 offset=0 imm=-4
#line 78 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=733 dst=r1 src=r0 offset=0 imm=0
#line 82 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_CALL pc=735 dst=r0 src=r0 offset=0 imm=3
#line 82 "sample/map.c"
    r0 = test_maps_helpers[3].address
#line 82 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 82 "sample/map.c"
    if ((test_maps_helpers[3].tail_call) && (r0 == 0))
#line 82 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=736 dst=r6 src=r0 offset=0 imm=0
#line 82 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=737 dst=r3 src=r6 offset=0 imm=0
#line 82 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=738 dst=r3 src=r0 offset=0 imm=32
#line 82 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=739 dst=r3 src=r0 offset=0 imm=32
#line 82 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=740 dst=r3 src=r0 offset=43 imm=-1
#line 83 "sample/map.c"
    if ((int64_t)r3 > (int64_t)IMMEDIATE(-1))
#line 83 "sample/map.c"
        goto label_50;
        // EBPF_OP_LDDW pc=741 dst=r1 src=r0 offset=0 imm=1684369010
#line 83 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=743 dst=r10 src=r1 offset=-40 imm=0
#line 84 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=744 dst=r1 src=r0 offset=0 imm=544040300
#line 84 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=746 dst=r10 src=r1 offset=-48 imm=0
#line 84 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=747 dst=r1 src=r0 offset=0 imm=1701602660
#line 84 "sample/map.c"
    r1 = (uint64_t)7304668671210448228;
label_48:
    // EBPF_OP_STXDW pc=749 dst=r10 src=r1 offset=-56 imm=0
#line 84 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=750 dst=r1 src=r0 offset=0 imm=1600548962
#line 84 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=752 dst=r10 src=r1 offset=-64 imm=0
#line 84 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=753 dst=r1 src=r10 offset=0 imm=0
#line 84 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=754 dst=r1 src=r0 offset=0 imm=-64
#line 84 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=755 dst=r2 src=r0 offset=0 imm=32
#line 84 "sample/map.c"
    r2 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=756 dst=r0 src=r0 offset=0 imm=13
#line 84 "sample/map.c"
    r0 = test_maps_helpers[4].address
#line 84 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 84 "sample/map.c"
    if ((test_maps_helpers[4].tail_call) && (r0 == 0))
#line 84 "sample/map.c"
        return 0;
label_49:
    // EBPF_OP_MOV64_IMM pc=757 dst=r1 src=r0 offset=0 imm=0
#line 84 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=758 dst=r10 src=r1 offset=-16 imm=0
#line 197 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint8_t)r1;
    // EBPF_OP_LDDW pc=759 dst=r1 src=r0 offset=0 imm=1701737077
#line 197 "sample/map.c"
    r1 = (uint64_t)7216209593501643381;
    // EBPF_OP_STXDW pc=761 dst=r10 src=r1 offset=-24 imm=0
#line 197 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=762 dst=r1 src=r0 offset=0 imm=1213415752
#line 197 "sample/map.c"
    r1 = (uint64_t)8387235364025352520;
    // EBPF_OP_STXDW pc=764 dst=r10 src=r1 offset=-32 imm=0
#line 197 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=765 dst=r1 src=r0 offset=0 imm=1380274271
#line 197 "sample/map.c"
    r1 = (uint64_t)6869485056696864863;
    // EBPF_OP_STXDW pc=767 dst=r10 src=r1 offset=-40 imm=0
#line 197 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=768 dst=r1 src=r0 offset=0 imm=1885433120
#line 197 "sample/map.c"
    r1 = (uint64_t)6148060143522245920;
    // EBPF_OP_STXDW pc=770 dst=r10 src=r1 offset=-48 imm=0
#line 197 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=771 dst=r1 src=r0 offset=0 imm=1279349317
#line 197 "sample/map.c"
    r1 = (uint64_t)8245921731643003461;
    // EBPF_OP_STXDW pc=773 dst=r10 src=r1 offset=-56 imm=0
#line 197 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=774 dst=r1 src=r0 offset=0 imm=1953719636
#line 197 "sample/map.c"
    r1 = (uint64_t)5639992313069659476;
    // EBPF_OP_STXDW pc=776 dst=r10 src=r1 offset=-64 imm=0
#line 197 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=777 dst=r3 src=r6 offset=0 imm=0
#line 197 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=778 dst=r3 src=r0 offset=0 imm=32
#line 197 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=779 dst=r3 src=r0 offset=0 imm=32
#line 197 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=780 dst=r1 src=r10 offset=0 imm=0
#line 197 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=781 dst=r1 src=r0 offset=0 imm=-64
#line 197 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=782 dst=r2 src=r0 offset=0 imm=49
#line 197 "sample/map.c"
    r2 = IMMEDIATE(49);
    // EBPF_OP_JA pc=783 dst=r0 src=r0 offset=-683 imm=0
#line 197 "sample/map.c"
    goto label_7;
label_50:
    // EBPF_OP_MOV64_REG pc=784 dst=r2 src=r10 offset=0 imm=0
#line 197 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=785 dst=r2 src=r0 offset=0 imm=-4
#line 197 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=786 dst=r3 src=r10 offset=0 imm=0
#line 197 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=787 dst=r3 src=r0 offset=0 imm=-68
#line 197 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=788 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_MOV64_IMM pc=790 dst=r4 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=791 dst=r0 src=r0 offset=0 imm=2
#line 88 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 88 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 88 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 88 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=792 dst=r6 src=r0 offset=0 imm=0
#line 88 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=793 dst=r3 src=r6 offset=0 imm=0
#line 88 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=794 dst=r3 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=795 dst=r3 src=r0 offset=0 imm=32
#line 88 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=796 dst=r3 src=r0 offset=1 imm=-1
#line 89 "sample/map.c"
    if ((int64_t)r3 > (int64_t)IMMEDIATE(-1))
#line 89 "sample/map.c"
        goto label_51;
        // EBPF_OP_JA pc=797 dst=r0 src=r0 offset=-103 imm=0
#line 89 "sample/map.c"
    goto label_44;
label_51:
    // EBPF_OP_MOV64_REG pc=798 dst=r2 src=r10 offset=0 imm=0
#line 89 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=799 dst=r2 src=r0 offset=0 imm=-4
#line 89 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=800 dst=r1 src=r0 offset=0 imm=0
#line 99 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_CALL pc=802 dst=r0 src=r0 offset=0 imm=4
#line 99 "sample/map.c"
    r0 = test_maps_helpers[5].address
#line 99 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 99 "sample/map.c"
    if ((test_maps_helpers[5].tail_call) && (r0 == 0))
#line 99 "sample/map.c"
        return 0;
        // EBPF_OP_JNE_IMM pc=803 dst=r0 src=r0 offset=23 imm=0
#line 100 "sample/map.c"
    if (r0 != IMMEDIATE(0))
#line 100 "sample/map.c"
        goto label_52;
        // EBPF_OP_MOV64_IMM pc=804 dst=r1 src=r0 offset=0 imm=0
#line 100 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=805 dst=r10 src=r1 offset=-20 imm=0
#line 101 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-20)) = (uint8_t)r1;
    // EBPF_OP_MOV64_IMM pc=806 dst=r1 src=r0 offset=0 imm=1280070990
#line 101 "sample/map.c"
    r1 = IMMEDIATE(1280070990);
    // EBPF_OP_STXW pc=807 dst=r10 src=r1 offset=-24 imm=0
#line 101 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=808 dst=r1 src=r0 offset=0 imm=1920300133
#line 101 "sample/map.c"
    r1 = (uint64_t)2334102031925867621;
    // EBPF_OP_STXDW pc=810 dst=r10 src=r1 offset=-32 imm=0
#line 101 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=811 dst=r1 src=r0 offset=0 imm=1818582885
#line 101 "sample/map.c"
    r1 = (uint64_t)8223693201956233061;
    // EBPF_OP_STXDW pc=813 dst=r10 src=r1 offset=-40 imm=0
#line 101 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=814 dst=r1 src=r0 offset=0 imm=1683973230
#line 101 "sample/map.c"
    r1 = (uint64_t)8387229063778886766;
    // EBPF_OP_STXDW pc=816 dst=r10 src=r1 offset=-48 imm=0
#line 101 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=817 dst=r1 src=r0 offset=0 imm=1802465132
#line 101 "sample/map.c"
    r1 = (uint64_t)7016450394082471788;
    // EBPF_OP_STXDW pc=819 dst=r10 src=r1 offset=-56 imm=0
#line 101 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=820 dst=r1 src=r0 offset=0 imm=1600548962
#line 101 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=822 dst=r10 src=r1 offset=-64 imm=0
#line 101 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=823 dst=r1 src=r10 offset=0 imm=0
#line 101 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=824 dst=r1 src=r0 offset=0 imm=-64
#line 101 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=825 dst=r2 src=r0 offset=0 imm=45
#line 101 "sample/map.c"
    r2 = IMMEDIATE(45);
    // EBPF_OP_JA pc=826 dst=r0 src=r0 offset=-100 imm=0
#line 101 "sample/map.c"
    goto label_46;
label_52:
    // EBPF_OP_MOV64_IMM pc=827 dst=r8 src=r0 offset=0 imm=0
#line 101 "sample/map.c"
    r8 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=828 dst=r10 src=r8 offset=-4 imm=0
#line 101 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r8;
    // EBPF_OP_MOV64_IMM pc=829 dst=r1 src=r0 offset=0 imm=1
#line 101 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=830 dst=r10 src=r1 offset=-68 imm=0
#line 111 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-68)) = (uint32_t)r1;
    // EBPF_OP_MOV64_IMM pc=831 dst=r9 src=r0 offset=0 imm=11
#line 111 "sample/map.c"
    r9 = IMMEDIATE(11);
label_53:
    // EBPF_OP_MOV64_REG pc=832 dst=r2 src=r10 offset=0 imm=0
#line 111 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=833 dst=r2 src=r0 offset=0 imm=-4
#line 111 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=834 dst=r3 src=r10 offset=0 imm=0
#line 111 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=835 dst=r3 src=r0 offset=0 imm=-68
#line 111 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=836 dst=r1 src=r0 offset=0 imm=0
#line 116 "sample/map.c"
    r1 = POINTER(_maps[4].address);
    // EBPF_OP_MOV64_IMM pc=838 dst=r4 src=r0 offset=0 imm=0
#line 116 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=839 dst=r0 src=r0 offset=0 imm=2
#line 116 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 116 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 116 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 116 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=840 dst=r6 src=r0 offset=0 imm=0
#line 116 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=841 dst=r7 src=r6 offset=0 imm=0
#line 116 "sample/map.c"
    r7 = r6;
    // EBPF_OP_LSH64_IMM pc=842 dst=r7 src=r0 offset=0 imm=32
#line 116 "sample/map.c"
    r7 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=843 dst=r7 src=r0 offset=0 imm=32
#line 116 "sample/map.c"
    r7 = (int64_t)r7 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_REG pc=844 dst=r8 src=r7 offset=72 imm=0
#line 117 "sample/map.c"
    if ((int64_t)r8 > (int64_t)r7)
#line 117 "sample/map.c"
        goto label_57;
        // EBPF_OP_LDXW pc=845 dst=r1 src=r10 offset=-4 imm=0
#line 115 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_ADD64_IMM pc=846 dst=r1 src=r0 offset=0 imm=1
#line 115 "sample/map.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXW pc=847 dst=r10 src=r1 offset=-4 imm=0
#line 115 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_LSH64_IMM pc=848 dst=r1 src=r0 offset=0 imm=32
#line 115 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=849 dst=r1 src=r0 offset=0 imm=32
#line 115 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JGT_REG pc=850 dst=r9 src=r1 offset=-19 imm=0
#line 115 "sample/map.c"
    if (r9 > r1)
#line 115 "sample/map.c"
        goto label_53;
        // EBPF_OP_MOV64_IMM pc=851 dst=r8 src=r0 offset=0 imm=0
#line 115 "sample/map.c"
    r8 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=852 dst=r10 src=r8 offset=-4 imm=0
#line 115 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r8;
    // EBPF_OP_MOV64_IMM pc=853 dst=r1 src=r0 offset=0 imm=1
#line 115 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=854 dst=r10 src=r1 offset=-68 imm=0
#line 111 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-68)) = (uint32_t)r1;
    // EBPF_OP_MOV64_IMM pc=855 dst=r9 src=r0 offset=0 imm=11
#line 111 "sample/map.c"
    r9 = IMMEDIATE(11);
label_54:
    // EBPF_OP_MOV64_REG pc=856 dst=r2 src=r10 offset=0 imm=0
#line 111 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=857 dst=r2 src=r0 offset=0 imm=-4
#line 111 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=858 dst=r3 src=r10 offset=0 imm=0
#line 111 "sample/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=859 dst=r3 src=r0 offset=0 imm=-68
#line 111 "sample/map.c"
    r3 += IMMEDIATE(-68);
    // EBPF_OP_LDDW pc=860 dst=r1 src=r0 offset=0 imm=0
#line 116 "sample/map.c"
    r1 = POINTER(_maps[5].address);
    // EBPF_OP_MOV64_IMM pc=862 dst=r4 src=r0 offset=0 imm=0
#line 116 "sample/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=863 dst=r0 src=r0 offset=0 imm=2
#line 116 "sample/map.c"
    r0 = test_maps_helpers[0].address
#line 116 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 116 "sample/map.c"
    if ((test_maps_helpers[0].tail_call) && (r0 == 0))
#line 116 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=864 dst=r6 src=r0 offset=0 imm=0
#line 116 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=865 dst=r7 src=r6 offset=0 imm=0
#line 116 "sample/map.c"
    r7 = r6;
    // EBPF_OP_LSH64_IMM pc=866 dst=r7 src=r0 offset=0 imm=32
#line 116 "sample/map.c"
    r7 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=867 dst=r7 src=r0 offset=0 imm=32
#line 116 "sample/map.c"
    r7 = (int64_t)r7 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_REG pc=868 dst=r8 src=r7 offset=85 imm=0
#line 117 "sample/map.c"
    if ((int64_t)r8 > (int64_t)r7)
#line 117 "sample/map.c"
        goto label_58;
        // EBPF_OP_LDXW pc=869 dst=r1 src=r10 offset=-4 imm=0
#line 115 "sample/map.c"
    r1 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_ADD64_IMM pc=870 dst=r1 src=r0 offset=0 imm=1
#line 115 "sample/map.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXW pc=871 dst=r10 src=r1 offset=-4 imm=0
#line 115 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_LSH64_IMM pc=872 dst=r1 src=r0 offset=0 imm=32
#line 115 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=873 dst=r1 src=r0 offset=0 imm=32
#line 115 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JGT_REG pc=874 dst=r9 src=r1 offset=-19 imm=0
#line 115 "sample/map.c"
    if (r9 > r1)
#line 115 "sample/map.c"
        goto label_54;
        // EBPF_OP_MOV64_IMM pc=875 dst=r1 src=r0 offset=0 imm=0
#line 115 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=876 dst=r10 src=r1 offset=-4 imm=0
#line 167 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=877 dst=r2 src=r10 offset=0 imm=0
#line 167 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=878 dst=r2 src=r0 offset=0 imm=-4
#line 167 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=879 dst=r1 src=r0 offset=0 imm=0
#line 167 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=881 dst=r0 src=r0 offset=0 imm=18
#line 167 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 167 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 167 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 167 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=882 dst=r6 src=r0 offset=0 imm=0
#line 167 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=883 dst=r4 src=r6 offset=0 imm=0
#line 167 "sample/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=884 dst=r4 src=r0 offset=0 imm=32
#line 167 "sample/map.c"
    r4 <<= IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=885 dst=r1 src=r4 offset=0 imm=0
#line 167 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=886 dst=r1 src=r0 offset=0 imm=32
#line 167 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_LDDW pc=887 dst=r2 src=r0 offset=0 imm=-7
#line 167 "sample/map.c"
    r2 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=889 dst=r1 src=r2 offset=105 imm=0
#line 167 "sample/map.c"
    if (r1 == r2)
#line 167 "sample/map.c"
        goto label_60;
label_55:
    // EBPF_OP_MOV64_IMM pc=890 dst=r1 src=r0 offset=0 imm=100
#line 167 "sample/map.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXH pc=891 dst=r10 src=r1 offset=-16 imm=0
#line 167 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=892 dst=r1 src=r0 offset=0 imm=1852994932
#line 167 "sample/map.c"
    r1 = (uint64_t)2675248565465544052;
    // EBPF_OP_STXDW pc=894 dst=r10 src=r1 offset=-24 imm=0
#line 167 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=895 dst=r1 src=r0 offset=0 imm=622883948
#line 167 "sample/map.c"
    r1 = (uint64_t)7309940759667438700;
    // EBPF_OP_STXDW pc=897 dst=r10 src=r1 offset=-32 imm=0
#line 167 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=898 dst=r1 src=r0 offset=0 imm=543649385
#line 167 "sample/map.c"
    r1 = (uint64_t)8463219665603620457;
    // EBPF_OP_STXDW pc=900 dst=r10 src=r1 offset=-40 imm=0
#line 167 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=901 dst=r1 src=r0 offset=0 imm=2019893357
#line 167 "sample/map.c"
    r1 = (uint64_t)8386658464824631405;
    // EBPF_OP_STXDW pc=903 dst=r10 src=r1 offset=-48 imm=0
#line 167 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=904 dst=r1 src=r0 offset=0 imm=1801807216
#line 167 "sample/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=906 dst=r10 src=r1 offset=-56 imm=0
#line 167 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=907 dst=r1 src=r0 offset=0 imm=1600548962
#line 167 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=909 dst=r10 src=r1 offset=-64 imm=0
#line 167 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_ARSH64_IMM pc=910 dst=r4 src=r0 offset=0 imm=32
#line 167 "sample/map.c"
    r4 = (int64_t)r4 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=911 dst=r1 src=r10 offset=0 imm=0
#line 167 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=912 dst=r1 src=r0 offset=0 imm=-64
#line 167 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=913 dst=r2 src=r0 offset=0 imm=50
#line 167 "sample/map.c"
    r2 = IMMEDIATE(50);
label_56:
    // EBPF_OP_MOV64_IMM pc=914 dst=r3 src=r0 offset=0 imm=-7
#line 167 "sample/map.c"
    r3 = IMMEDIATE(-7);
    // EBPF_OP_CALL pc=915 dst=r0 src=r0 offset=0 imm=14
#line 167 "sample/map.c"
    r0 = test_maps_helpers[7].address
#line 167 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 167 "sample/map.c"
    if ((test_maps_helpers[7].tail_call) && (r0 == 0))
#line 167 "sample/map.c"
        return 0;
        // EBPF_OP_JA pc=916 dst=r0 src=r0 offset=104 imm=0
#line 167 "sample/map.c"
    goto label_64;
label_57:
    // EBPF_OP_LDDW pc=917 dst=r1 src=r0 offset=0 imm=1684369010
#line 167 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=919 dst=r10 src=r1 offset=-40 imm=0
#line 118 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=920 dst=r1 src=r0 offset=0 imm=544040300
#line 118 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=922 dst=r10 src=r1 offset=-48 imm=0
#line 118 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=923 dst=r1 src=r0 offset=0 imm=1633972341
#line 118 "sample/map.c"
    r1 = (uint64_t)7304668671142817909;
    // EBPF_OP_STXDW pc=925 dst=r10 src=r1 offset=-56 imm=0
#line 118 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=926 dst=r1 src=r0 offset=0 imm=1600548962
#line 118 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=928 dst=r10 src=r1 offset=-64 imm=0
#line 118 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=929 dst=r1 src=r10 offset=0 imm=0
#line 118 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=930 dst=r1 src=r0 offset=0 imm=-64
#line 118 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=931 dst=r2 src=r0 offset=0 imm=32
#line 118 "sample/map.c"
    r2 = IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=932 dst=r3 src=r7 offset=0 imm=0
#line 118 "sample/map.c"
    r3 = r7;
    // EBPF_OP_CALL pc=933 dst=r0 src=r0 offset=0 imm=13
#line 118 "sample/map.c"
    r0 = test_maps_helpers[4].address
#line 118 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 118 "sample/map.c"
    if ((test_maps_helpers[4].tail_call) && (r0 == 0))
#line 118 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_IMM pc=934 dst=r1 src=r0 offset=0 imm=100
#line 118 "sample/map.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXH pc=935 dst=r10 src=r1 offset=-28 imm=0
#line 199 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-28)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=936 dst=r1 src=r0 offset=0 imm=622879845
#line 199 "sample/map.c"
    r1 = IMMEDIATE(622879845);
    // EBPF_OP_STXW pc=937 dst=r10 src=r1 offset=-32 imm=0
#line 199 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=938 dst=r1 src=r0 offset=0 imm=1701978184
#line 199 "sample/map.c"
    r1 = (uint64_t)7958552634295722056;
    // EBPF_OP_STXDW pc=940 dst=r10 src=r1 offset=-40 imm=0
#line 199 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=941 dst=r1 src=r0 offset=0 imm=1431456800
#line 199 "sample/map.c"
    r1 = (uint64_t)5999155752924761120;
    // EBPF_OP_STXDW pc=943 dst=r10 src=r1 offset=-48 imm=0
#line 199 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=944 dst=r1 src=r0 offset=0 imm=1919903264
#line 199 "sample/map.c"
    r1 = (uint64_t)8097873591115146784;
    // EBPF_OP_STXDW pc=946 dst=r10 src=r1 offset=-56 imm=0
#line 199 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=947 dst=r1 src=r0 offset=0 imm=1953719636
#line 199 "sample/map.c"
    r1 = (uint64_t)6148060143590532436;
    // EBPF_OP_STXDW pc=949 dst=r10 src=r1 offset=-64 imm=0
#line 199 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=950 dst=r1 src=r10 offset=0 imm=0
#line 199 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=951 dst=r1 src=r0 offset=0 imm=-64
#line 118 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=952 dst=r2 src=r0 offset=0 imm=38
#line 199 "sample/map.c"
    r2 = IMMEDIATE(38);
    // EBPF_OP_JA pc=953 dst=r0 src=r0 offset=39 imm=0
#line 199 "sample/map.c"
    goto label_59;
label_58:
    // EBPF_OP_LDDW pc=954 dst=r1 src=r0 offset=0 imm=1684369010
#line 199 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=956 dst=r10 src=r1 offset=-40 imm=0
#line 118 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=957 dst=r1 src=r0 offset=0 imm=544040300
#line 118 "sample/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=959 dst=r10 src=r1 offset=-48 imm=0
#line 118 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=960 dst=r1 src=r0 offset=0 imm=1633972341
#line 118 "sample/map.c"
    r1 = (uint64_t)7304668671142817909;
    // EBPF_OP_STXDW pc=962 dst=r10 src=r1 offset=-56 imm=0
#line 118 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=963 dst=r1 src=r0 offset=0 imm=1600548962
#line 118 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=965 dst=r10 src=r1 offset=-64 imm=0
#line 118 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=966 dst=r1 src=r10 offset=0 imm=0
#line 118 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=967 dst=r1 src=r0 offset=0 imm=-64
#line 118 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=968 dst=r2 src=r0 offset=0 imm=32
#line 118 "sample/map.c"
    r2 = IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=969 dst=r3 src=r7 offset=0 imm=0
#line 118 "sample/map.c"
    r3 = r7;
    // EBPF_OP_CALL pc=970 dst=r0 src=r0 offset=0 imm=13
#line 118 "sample/map.c"
    r0 = test_maps_helpers[4].address
#line 118 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 118 "sample/map.c"
    if ((test_maps_helpers[4].tail_call) && (r0 == 0))
#line 118 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_IMM pc=971 dst=r1 src=r0 offset=0 imm=0
#line 118 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=972 dst=r10 src=r1 offset=-20 imm=0
#line 200 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-20)) = (uint8_t)r1;
    // EBPF_OP_MOV64_IMM pc=973 dst=r1 src=r0 offset=0 imm=1680154724
#line 200 "sample/map.c"
    r1 = IMMEDIATE(1680154724);
    // EBPF_OP_STXW pc=974 dst=r10 src=r1 offset=-24 imm=0
#line 200 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=975 dst=r1 src=r0 offset=0 imm=1952805408
#line 200 "sample/map.c"
    r1 = (uint64_t)7308905094058439200;
    // EBPF_OP_STXDW pc=977 dst=r10 src=r1 offset=-32 imm=0
#line 200 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=978 dst=r1 src=r0 offset=0 imm=1599426627
#line 200 "sample/map.c"
    r1 = (uint64_t)5211580972890673219;
    // EBPF_OP_STXDW pc=980 dst=r10 src=r1 offset=-40 imm=0
#line 200 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=981 dst=r1 src=r0 offset=0 imm=1431456800
#line 200 "sample/map.c"
    r1 = (uint64_t)5928232854886698016;
    // EBPF_OP_STXDW pc=983 dst=r10 src=r1 offset=-48 imm=0
#line 200 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=984 dst=r1 src=r0 offset=0 imm=1919903264
#line 200 "sample/map.c"
    r1 = (uint64_t)8097873591115146784;
    // EBPF_OP_STXDW pc=986 dst=r10 src=r1 offset=-56 imm=0
#line 200 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=987 dst=r1 src=r0 offset=0 imm=1953719636
#line 200 "sample/map.c"
    r1 = (uint64_t)6148060143590532436;
    // EBPF_OP_STXDW pc=989 dst=r10 src=r1 offset=-64 imm=0
#line 200 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=990 dst=r1 src=r10 offset=0 imm=0
#line 200 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=991 dst=r1 src=r0 offset=0 imm=-64
#line 118 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=992 dst=r2 src=r0 offset=0 imm=45
#line 200 "sample/map.c"
    r2 = IMMEDIATE(45);
label_59:
    // EBPF_OP_MOV64_REG pc=993 dst=r3 src=r7 offset=0 imm=0
#line 200 "sample/map.c"
    r3 = r7;
    // EBPF_OP_JA pc=994 dst=r0 src=r0 offset=-894 imm=0
#line 200 "sample/map.c"
    goto label_7;
label_60:
    // EBPF_OP_LDXW pc=995 dst=r3 src=r10 offset=-4 imm=0
#line 167 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=996 dst=r3 src=r0 offset=47 imm=0
#line 167 "sample/map.c"
    if (r3 == IMMEDIATE(0))
#line 167 "sample/map.c"
        goto label_65;
label_61:
    // EBPF_OP_LDDW pc=997 dst=r1 src=r0 offset=0 imm=1852404835
#line 167 "sample/map.c"
    r1 = (uint64_t)7216209606537213027;
    // EBPF_OP_STXDW pc=999 dst=r10 src=r1 offset=-32 imm=0
#line 167 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1000 dst=r1 src=r0 offset=0 imm=543434016
#line 167 "sample/map.c"
    r1 = (uint64_t)7309474570952779040;
    // EBPF_OP_STXDW pc=1002 dst=r10 src=r1 offset=-40 imm=0
#line 167 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1003 dst=r1 src=r0 offset=0 imm=1701978221
#line 167 "sample/map.c"
    r1 = (uint64_t)7958552634295722093;
    // EBPF_OP_STXDW pc=1005 dst=r10 src=r1 offset=-48 imm=0
#line 167 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1006 dst=r1 src=r0 offset=0 imm=1801807216
#line 167 "sample/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=1008 dst=r10 src=r1 offset=-56 imm=0
#line 167 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1009 dst=r1 src=r0 offset=0 imm=1600548962
#line 167 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1011 dst=r10 src=r1 offset=-64 imm=0
#line 167 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_IMM pc=1012 dst=r1 src=r0 offset=0 imm=0
#line 167 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=1013 dst=r10 src=r1 offset=-24 imm=0
#line 167 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint8_t)r1;
    // EBPF_OP_MOV64_REG pc=1014 dst=r1 src=r10 offset=0 imm=0
#line 167 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1015 dst=r1 src=r0 offset=0 imm=-64
#line 167 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1016 dst=r2 src=r0 offset=0 imm=41
#line 167 "sample/map.c"
    r2 = IMMEDIATE(41);
label_62:
    // EBPF_OP_MOV64_IMM pc=1017 dst=r4 src=r0 offset=0 imm=0
#line 167 "sample/map.c"
    r4 = IMMEDIATE(0);
label_63:
    // EBPF_OP_CALL pc=1018 dst=r0 src=r0 offset=0 imm=14
#line 167 "sample/map.c"
    r0 = test_maps_helpers[7].address
#line 167 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 167 "sample/map.c"
    if ((test_maps_helpers[7].tail_call) && (r0 == 0))
#line 167 "sample/map.c"
        return 0;
        // EBPF_OP_LDDW pc=1019 dst=r6 src=r0 offset=0 imm=-1
#line 167 "sample/map.c"
    r6 = (uint64_t)4294967295;
label_64:
    // EBPF_OP_MOV64_REG pc=1021 dst=r3 src=r6 offset=0 imm=0
#line 202 "sample/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=1022 dst=r3 src=r0 offset=0 imm=32
#line 202 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=1023 dst=r3 src=r0 offset=0 imm=32
#line 202 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=1024 dst=r3 src=r0 offset=627 imm=-1
#line 202 "sample/map.c"
    if ((int64_t)r3 > (int64_t)IMMEDIATE(-1))
#line 202 "sample/map.c"
        goto label_88;
        // EBPF_OP_LDDW pc=1025 dst=r1 src=r0 offset=0 imm=1684369010
#line 202 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=1027 dst=r10 src=r1 offset=-32 imm=0
#line 202 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1028 dst=r1 src=r0 offset=0 imm=541414725
#line 202 "sample/map.c"
    r1 = (uint64_t)8463501140578096453;
    // EBPF_OP_STXDW pc=1030 dst=r10 src=r1 offset=-40 imm=0
#line 202 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1031 dst=r1 src=r0 offset=0 imm=1634541682
#line 202 "sample/map.c"
    r1 = (uint64_t)6147730633380405362;
    // EBPF_OP_STXDW pc=1033 dst=r10 src=r1 offset=-48 imm=0
#line 202 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1034 dst=r1 src=r0 offset=0 imm=1330667336
#line 202 "sample/map.c"
    r1 = (uint64_t)8027138915134627656;
    // EBPF_OP_STXDW pc=1036 dst=r10 src=r1 offset=-56 imm=0
#line 202 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1037 dst=r1 src=r0 offset=0 imm=1953719636
#line 202 "sample/map.c"
    r1 = (uint64_t)6004793778491319636;
    // EBPF_OP_STXDW pc=1039 dst=r10 src=r1 offset=-64 imm=0
#line 202 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1040 dst=r1 src=r10 offset=0 imm=0
#line 202 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1041 dst=r1 src=r0 offset=0 imm=-64
#line 202 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1042 dst=r2 src=r0 offset=0 imm=40
#line 202 "sample/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_JA pc=1043 dst=r0 src=r0 offset=-943 imm=0
#line 202 "sample/map.c"
    goto label_7;
label_65:
    // EBPF_OP_MOV64_IMM pc=1044 dst=r7 src=r0 offset=0 imm=0
#line 202 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1045 dst=r10 src=r7 offset=-4 imm=0
#line 168 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=1046 dst=r2 src=r10 offset=0 imm=0
#line 168 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1047 dst=r2 src=r0 offset=0 imm=-4
#line 168 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1048 dst=r1 src=r0 offset=0 imm=0
#line 168 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=1050 dst=r0 src=r0 offset=0 imm=17
#line 168 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 168 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 168 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 168 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1051 dst=r6 src=r0 offset=0 imm=0
#line 168 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1052 dst=r4 src=r6 offset=0 imm=0
#line 168 "sample/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=1053 dst=r4 src=r0 offset=0 imm=32
#line 168 "sample/map.c"
    r4 <<= IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=1054 dst=r1 src=r4 offset=0 imm=0
#line 168 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=1055 dst=r1 src=r0 offset=0 imm=32
#line 168 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_LDDW pc=1056 dst=r2 src=r0 offset=0 imm=-7
#line 168 "sample/map.c"
    r2 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=1058 dst=r1 src=r2 offset=24 imm=0
#line 168 "sample/map.c"
    if (r1 == r2)
#line 168 "sample/map.c"
        goto label_67;
label_66:
    // EBPF_OP_STXB pc=1059 dst=r10 src=r7 offset=-16 imm=0
#line 168 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint8_t)r7;
    // EBPF_OP_LDDW pc=1060 dst=r1 src=r0 offset=0 imm=1701737077
#line 168 "sample/map.c"
    r1 = (uint64_t)7216209593501643381;
    // EBPF_OP_STXDW pc=1062 dst=r10 src=r1 offset=-24 imm=0
#line 168 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1063 dst=r1 src=r0 offset=0 imm=1680154740
#line 168 "sample/map.c"
    r1 = (uint64_t)8387235364492091508;
    // EBPF_OP_STXDW pc=1065 dst=r10 src=r1 offset=-32 imm=0
#line 168 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1066 dst=r1 src=r0 offset=0 imm=1914726254
#line 168 "sample/map.c"
    r1 = (uint64_t)7815279607914981230;
    // EBPF_OP_STXDW pc=1068 dst=r10 src=r1 offset=-40 imm=0
#line 168 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1069 dst=r1 src=r0 offset=0 imm=1886938400
#line 168 "sample/map.c"
    r1 = (uint64_t)7598807758610654496;
    // EBPF_OP_STXDW pc=1071 dst=r10 src=r1 offset=-48 imm=0
#line 168 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1072 dst=r1 src=r0 offset=0 imm=1601204080
#line 168 "sample/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=1074 dst=r10 src=r1 offset=-56 imm=0
#line 168 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1075 dst=r1 src=r0 offset=0 imm=1600548962
#line 168 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1077 dst=r10 src=r1 offset=-64 imm=0
#line 168 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_ARSH64_IMM pc=1078 dst=r4 src=r0 offset=0 imm=32
#line 168 "sample/map.c"
    r4 = (int64_t)r4 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=1079 dst=r1 src=r10 offset=0 imm=0
#line 168 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1080 dst=r1 src=r0 offset=0 imm=-64
#line 168 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1081 dst=r2 src=r0 offset=0 imm=49
#line 168 "sample/map.c"
    r2 = IMMEDIATE(49);
    // EBPF_OP_JA pc=1082 dst=r0 src=r0 offset=-169 imm=0
#line 168 "sample/map.c"
    goto label_56;
label_67:
    // EBPF_OP_LDXW pc=1083 dst=r3 src=r10 offset=-4 imm=0
#line 168 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1084 dst=r3 src=r0 offset=19 imm=0
#line 168 "sample/map.c"
    if (r3 == IMMEDIATE(0))
#line 168 "sample/map.c"
        goto label_69;
label_68:
    // EBPF_OP_LDDW pc=1085 dst=r1 src=r0 offset=0 imm=1735289204
#line 168 "sample/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=1087 dst=r10 src=r1 offset=-32 imm=0
#line 168 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1088 dst=r1 src=r0 offset=0 imm=1696621605
#line 168 "sample/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=1090 dst=r10 src=r1 offset=-40 imm=0
#line 168 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1091 dst=r1 src=r0 offset=0 imm=1952805408
#line 168 "sample/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=1093 dst=r10 src=r1 offset=-48 imm=0
#line 168 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1094 dst=r1 src=r0 offset=0 imm=1601204080
#line 168 "sample/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=1096 dst=r10 src=r1 offset=-56 imm=0
#line 168 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1097 dst=r1 src=r0 offset=0 imm=1600548962
#line 168 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1099 dst=r10 src=r1 offset=-64 imm=0
#line 168 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1100 dst=r1 src=r10 offset=0 imm=0
#line 168 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1101 dst=r1 src=r0 offset=0 imm=-64
#line 168 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1102 dst=r2 src=r0 offset=0 imm=40
#line 168 "sample/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_JA pc=1103 dst=r0 src=r0 offset=-87 imm=0
#line 168 "sample/map.c"
    goto label_62;
label_69:
    // EBPF_OP_MOV64_IMM pc=1104 dst=r7 src=r0 offset=0 imm=0
#line 168 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1105 dst=r10 src=r7 offset=-4 imm=0
#line 171 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=1106 dst=r2 src=r10 offset=0 imm=0
#line 171 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1107 dst=r2 src=r0 offset=0 imm=-4
#line 171 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1108 dst=r1 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=1110 dst=r3 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1111 dst=r0 src=r0 offset=0 imm=16
#line 171 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 171 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 171 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 171 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1112 dst=r6 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1113 dst=r1 src=r6 offset=0 imm=0
#line 171 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=1114 dst=r1 src=r0 offset=0 imm=32
#line 171 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1115 dst=r1 src=r0 offset=0 imm=32
#line 171 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=1116 dst=r1 src=r0 offset=33 imm=0
#line 171 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 171 "sample/map.c"
        goto label_73;
label_70:
    // EBPF_OP_MOV64_IMM pc=1117 dst=r1 src=r0 offset=0 imm=25637
#line 171 "sample/map.c"
    r1 = IMMEDIATE(25637);
    // EBPF_OP_STXH pc=1118 dst=r10 src=r1 offset=-12 imm=0
#line 171 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-12)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=1119 dst=r1 src=r0 offset=0 imm=543450478
#line 171 "sample/map.c"
    r1 = IMMEDIATE(543450478);
    // EBPF_OP_STXW pc=1120 dst=r10 src=r1 offset=-16 imm=0
#line 171 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=1121 dst=r1 src=r0 offset=0 imm=1914725413
#line 171 "sample/map.c"
    r1 = (uint64_t)8247626271654175781;
    // EBPF_OP_STXDW pc=1123 dst=r10 src=r1 offset=-24 imm=0
#line 171 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1124 dst=r1 src=r0 offset=0 imm=1667592312
#line 171 "sample/map.c"
    r1 = (uint64_t)2334102057442963576;
    // EBPF_OP_STXDW pc=1126 dst=r10 src=r1 offset=-32 imm=0
#line 171 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1127 dst=r1 src=r0 offset=0 imm=543649385
#line 171 "sample/map.c"
    r1 = (uint64_t)7286934307705679465;
    // EBPF_OP_STXDW pc=1129 dst=r10 src=r1 offset=-40 imm=0
#line 171 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1130 dst=r1 src=r0 offset=0 imm=1852383341
#line 171 "sample/map.c"
    r1 = (uint64_t)8390880602192683117;
    // EBPF_OP_STXDW pc=1132 dst=r10 src=r1 offset=-48 imm=0
#line 171 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1133 dst=r1 src=r0 offset=0 imm=1752397168
#line 171 "sample/map.c"
    r1 = (uint64_t)7308327755764168048;
    // EBPF_OP_STXDW pc=1135 dst=r10 src=r1 offset=-56 imm=0
#line 171 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1136 dst=r1 src=r0 offset=0 imm=1600548962
#line 171 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1138 dst=r10 src=r1 offset=-64 imm=0
#line 171 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_STXB pc=1139 dst=r10 src=r7 offset=-10 imm=0
#line 171 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-10)) = (uint8_t)r7;
    // EBPF_OP_LDXW pc=1140 dst=r3 src=r10 offset=-4 imm=0
#line 171 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=1141 dst=r5 src=r6 offset=0 imm=0
#line 171 "sample/map.c"
    r5 = r6;
    // EBPF_OP_LSH64_IMM pc=1142 dst=r5 src=r0 offset=0 imm=32
#line 171 "sample/map.c"
    r5 <<= IMMEDIATE(32);
label_71:
    // EBPF_OP_ARSH64_IMM pc=1143 dst=r5 src=r0 offset=0 imm=32
#line 171 "sample/map.c"
    r5 = (int64_t)r5 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=1144 dst=r1 src=r10 offset=0 imm=0
#line 171 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1145 dst=r1 src=r0 offset=0 imm=-64
#line 171 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1146 dst=r2 src=r0 offset=0 imm=55
#line 171 "sample/map.c"
    r2 = IMMEDIATE(55);
    // EBPF_OP_MOV64_IMM pc=1147 dst=r4 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r4 = IMMEDIATE(0);
label_72:
    // EBPF_OP_CALL pc=1148 dst=r0 src=r0 offset=0 imm=15
#line 171 "sample/map.c"
    r0 = test_maps_helpers[10].address
#line 171 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 171 "sample/map.c"
    if ((test_maps_helpers[10].tail_call) && (r0 == 0))
#line 171 "sample/map.c"
        return 0;
        // EBPF_OP_JA pc=1149 dst=r0 src=r0 offset=-129 imm=0
#line 171 "sample/map.c"
    goto label_64;
label_73:
    // EBPF_OP_MOV64_IMM pc=1150 dst=r1 src=r0 offset=0 imm=1
#line 171 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=1151 dst=r10 src=r1 offset=-4 imm=0
#line 171 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1152 dst=r2 src=r10 offset=0 imm=0
#line 171 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1153 dst=r2 src=r0 offset=0 imm=-4
#line 171 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1154 dst=r1 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=1156 dst=r3 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1157 dst=r0 src=r0 offset=0 imm=16
#line 171 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 171 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 171 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 171 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1158 dst=r6 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1159 dst=r1 src=r6 offset=0 imm=0
#line 171 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=1160 dst=r1 src=r0 offset=0 imm=32
#line 171 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1161 dst=r1 src=r0 offset=0 imm=32
#line 171 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=1162 dst=r1 src=r0 offset=1 imm=0
#line 171 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 171 "sample/map.c"
        goto label_74;
        // EBPF_OP_JA pc=1163 dst=r0 src=r0 offset=-47 imm=0
#line 171 "sample/map.c"
    goto label_70;
label_74:
    // EBPF_OP_MOV64_IMM pc=1164 dst=r1 src=r0 offset=0 imm=2
#line 171 "sample/map.c"
    r1 = IMMEDIATE(2);
    // EBPF_OP_STXW pc=1165 dst=r10 src=r1 offset=-4 imm=0
#line 171 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1166 dst=r2 src=r10 offset=0 imm=0
#line 171 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1167 dst=r2 src=r0 offset=0 imm=-4
#line 171 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1168 dst=r1 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=1170 dst=r3 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1171 dst=r0 src=r0 offset=0 imm=16
#line 171 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 171 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 171 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 171 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1172 dst=r6 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1173 dst=r1 src=r6 offset=0 imm=0
#line 171 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=1174 dst=r1 src=r0 offset=0 imm=32
#line 171 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1175 dst=r1 src=r0 offset=0 imm=32
#line 171 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1176 dst=r1 src=r0 offset=-60 imm=0
#line 171 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 171 "sample/map.c"
        goto label_70;
        // EBPF_OP_MOV64_IMM pc=1177 dst=r1 src=r0 offset=0 imm=3
#line 171 "sample/map.c"
    r1 = IMMEDIATE(3);
    // EBPF_OP_STXW pc=1178 dst=r10 src=r1 offset=-4 imm=0
#line 171 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1179 dst=r2 src=r10 offset=0 imm=0
#line 171 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1180 dst=r2 src=r0 offset=0 imm=-4
#line 171 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1181 dst=r1 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=1183 dst=r3 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1184 dst=r0 src=r0 offset=0 imm=16
#line 171 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 171 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 171 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 171 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1185 dst=r6 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1186 dst=r1 src=r6 offset=0 imm=0
#line 171 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=1187 dst=r1 src=r0 offset=0 imm=32
#line 171 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1188 dst=r1 src=r0 offset=0 imm=32
#line 171 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1189 dst=r1 src=r0 offset=-73 imm=0
#line 171 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 171 "sample/map.c"
        goto label_70;
        // EBPF_OP_MOV64_IMM pc=1190 dst=r1 src=r0 offset=0 imm=4
#line 171 "sample/map.c"
    r1 = IMMEDIATE(4);
    // EBPF_OP_STXW pc=1191 dst=r10 src=r1 offset=-4 imm=0
#line 171 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1192 dst=r2 src=r10 offset=0 imm=0
#line 171 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1193 dst=r2 src=r0 offset=0 imm=-4
#line 171 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1194 dst=r1 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=1196 dst=r3 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1197 dst=r0 src=r0 offset=0 imm=16
#line 171 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 171 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 171 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 171 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1198 dst=r6 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1199 dst=r1 src=r6 offset=0 imm=0
#line 171 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=1200 dst=r1 src=r0 offset=0 imm=32
#line 171 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1201 dst=r1 src=r0 offset=0 imm=32
#line 171 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1202 dst=r1 src=r0 offset=-86 imm=0
#line 171 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 171 "sample/map.c"
        goto label_70;
        // EBPF_OP_MOV64_IMM pc=1203 dst=r1 src=r0 offset=0 imm=5
#line 171 "sample/map.c"
    r1 = IMMEDIATE(5);
    // EBPF_OP_STXW pc=1204 dst=r10 src=r1 offset=-4 imm=0
#line 171 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1205 dst=r2 src=r10 offset=0 imm=0
#line 171 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1206 dst=r2 src=r0 offset=0 imm=-4
#line 171 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1207 dst=r1 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=1209 dst=r3 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1210 dst=r0 src=r0 offset=0 imm=16
#line 171 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 171 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 171 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 171 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1211 dst=r6 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1212 dst=r1 src=r6 offset=0 imm=0
#line 171 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=1213 dst=r1 src=r0 offset=0 imm=32
#line 171 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1214 dst=r1 src=r0 offset=0 imm=32
#line 171 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1215 dst=r1 src=r0 offset=-99 imm=0
#line 171 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 171 "sample/map.c"
        goto label_70;
        // EBPF_OP_MOV64_IMM pc=1216 dst=r1 src=r0 offset=0 imm=6
#line 171 "sample/map.c"
    r1 = IMMEDIATE(6);
    // EBPF_OP_STXW pc=1217 dst=r10 src=r1 offset=-4 imm=0
#line 171 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1218 dst=r2 src=r10 offset=0 imm=0
#line 171 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1219 dst=r2 src=r0 offset=0 imm=-4
#line 171 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1220 dst=r1 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=1222 dst=r3 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1223 dst=r0 src=r0 offset=0 imm=16
#line 171 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 171 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 171 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 171 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1224 dst=r6 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1225 dst=r1 src=r6 offset=0 imm=0
#line 171 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=1226 dst=r1 src=r0 offset=0 imm=32
#line 171 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1227 dst=r1 src=r0 offset=0 imm=32
#line 171 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1228 dst=r1 src=r0 offset=-112 imm=0
#line 171 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 171 "sample/map.c"
        goto label_70;
        // EBPF_OP_MOV64_IMM pc=1229 dst=r1 src=r0 offset=0 imm=7
#line 171 "sample/map.c"
    r1 = IMMEDIATE(7);
    // EBPF_OP_STXW pc=1230 dst=r10 src=r1 offset=-4 imm=0
#line 171 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1231 dst=r2 src=r10 offset=0 imm=0
#line 171 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1232 dst=r2 src=r0 offset=0 imm=-4
#line 171 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1233 dst=r1 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=1235 dst=r3 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1236 dst=r0 src=r0 offset=0 imm=16
#line 171 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 171 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 171 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 171 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1237 dst=r6 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1238 dst=r1 src=r6 offset=0 imm=0
#line 171 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=1239 dst=r1 src=r0 offset=0 imm=32
#line 171 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1240 dst=r1 src=r0 offset=0 imm=32
#line 171 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1241 dst=r1 src=r0 offset=-125 imm=0
#line 171 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 171 "sample/map.c"
        goto label_70;
        // EBPF_OP_MOV64_IMM pc=1242 dst=r1 src=r0 offset=0 imm=8
#line 171 "sample/map.c"
    r1 = IMMEDIATE(8);
    // EBPF_OP_STXW pc=1243 dst=r10 src=r1 offset=-4 imm=0
#line 171 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1244 dst=r2 src=r10 offset=0 imm=0
#line 171 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1245 dst=r2 src=r0 offset=0 imm=-4
#line 171 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1246 dst=r1 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=1248 dst=r3 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1249 dst=r0 src=r0 offset=0 imm=16
#line 171 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 171 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 171 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 171 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1250 dst=r6 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1251 dst=r1 src=r6 offset=0 imm=0
#line 171 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=1252 dst=r1 src=r0 offset=0 imm=32
#line 171 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1253 dst=r1 src=r0 offset=0 imm=32
#line 171 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1254 dst=r1 src=r0 offset=-138 imm=0
#line 171 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 171 "sample/map.c"
        goto label_70;
        // EBPF_OP_MOV64_IMM pc=1255 dst=r1 src=r0 offset=0 imm=9
#line 171 "sample/map.c"
    r1 = IMMEDIATE(9);
    // EBPF_OP_STXW pc=1256 dst=r10 src=r1 offset=-4 imm=0
#line 171 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1257 dst=r2 src=r10 offset=0 imm=0
#line 171 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1258 dst=r2 src=r0 offset=0 imm=-4
#line 171 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1259 dst=r1 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=1261 dst=r3 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1262 dst=r0 src=r0 offset=0 imm=16
#line 171 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 171 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 171 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 171 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1263 dst=r6 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1264 dst=r1 src=r6 offset=0 imm=0
#line 171 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=1265 dst=r1 src=r0 offset=0 imm=32
#line 171 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1266 dst=r1 src=r0 offset=0 imm=32
#line 171 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1267 dst=r1 src=r0 offset=-151 imm=0
#line 171 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 171 "sample/map.c"
        goto label_70;
        // EBPF_OP_MOV64_IMM pc=1268 dst=r7 src=r0 offset=0 imm=10
#line 171 "sample/map.c"
    r7 = IMMEDIATE(10);
    // EBPF_OP_STXW pc=1269 dst=r10 src=r7 offset=-4 imm=0
#line 174 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=1270 dst=r2 src=r10 offset=0 imm=0
#line 174 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1271 dst=r2 src=r0 offset=0 imm=-4
#line 174 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_IMM pc=1272 dst=r8 src=r0 offset=0 imm=0
#line 174 "sample/map.c"
    r8 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=1273 dst=r1 src=r0 offset=0 imm=0
#line 174 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=1275 dst=r3 src=r0 offset=0 imm=0
#line 174 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1276 dst=r0 src=r0 offset=0 imm=16
#line 174 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 174 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 174 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 174 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1277 dst=r6 src=r0 offset=0 imm=0
#line 174 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1278 dst=r5 src=r6 offset=0 imm=0
#line 174 "sample/map.c"
    r5 = r6;
    // EBPF_OP_LSH64_IMM pc=1279 dst=r5 src=r0 offset=0 imm=32
#line 174 "sample/map.c"
    r5 <<= IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=1280 dst=r1 src=r5 offset=0 imm=0
#line 174 "sample/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=1281 dst=r1 src=r0 offset=0 imm=32
#line 174 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_LDDW pc=1282 dst=r2 src=r0 offset=0 imm=-29
#line 174 "sample/map.c"
    r2 = (uint64_t)4294967267;
    // EBPF_OP_JEQ_REG pc=1284 dst=r1 src=r2 offset=30 imm=0
#line 174 "sample/map.c"
    if (r1 == r2)
#line 174 "sample/map.c"
        goto label_75;
        // EBPF_OP_STXB pc=1285 dst=r10 src=r8 offset=-10 imm=0
#line 174 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-10)) = (uint8_t)r8;
    // EBPF_OP_MOV64_IMM pc=1286 dst=r1 src=r0 offset=0 imm=25637
#line 174 "sample/map.c"
    r1 = IMMEDIATE(25637);
    // EBPF_OP_STXH pc=1287 dst=r10 src=r1 offset=-12 imm=0
#line 174 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-12)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=1288 dst=r1 src=r0 offset=0 imm=543450478
#line 174 "sample/map.c"
    r1 = IMMEDIATE(543450478);
    // EBPF_OP_STXW pc=1289 dst=r10 src=r1 offset=-16 imm=0
#line 174 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=1290 dst=r1 src=r0 offset=0 imm=1914725413
#line 174 "sample/map.c"
    r1 = (uint64_t)8247626271654175781;
    // EBPF_OP_STXDW pc=1292 dst=r10 src=r1 offset=-24 imm=0
#line 174 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1293 dst=r1 src=r0 offset=0 imm=1667592312
#line 174 "sample/map.c"
    r1 = (uint64_t)2334102057442963576;
    // EBPF_OP_STXDW pc=1295 dst=r10 src=r1 offset=-32 imm=0
#line 174 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1296 dst=r1 src=r0 offset=0 imm=543649385
#line 174 "sample/map.c"
    r1 = (uint64_t)7286934307705679465;
    // EBPF_OP_STXDW pc=1298 dst=r10 src=r1 offset=-40 imm=0
#line 174 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1299 dst=r1 src=r0 offset=0 imm=1852383341
#line 174 "sample/map.c"
    r1 = (uint64_t)8390880602192683117;
    // EBPF_OP_STXDW pc=1301 dst=r10 src=r1 offset=-48 imm=0
#line 174 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1302 dst=r1 src=r0 offset=0 imm=1752397168
#line 174 "sample/map.c"
    r1 = (uint64_t)7308327755764168048;
    // EBPF_OP_STXDW pc=1304 dst=r10 src=r1 offset=-56 imm=0
#line 174 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1305 dst=r1 src=r0 offset=0 imm=1600548962
#line 174 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1307 dst=r10 src=r1 offset=-64 imm=0
#line 174 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=1308 dst=r3 src=r10 offset=-4 imm=0
#line 174 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_ARSH64_IMM pc=1309 dst=r5 src=r0 offset=0 imm=32
#line 174 "sample/map.c"
    r5 = (int64_t)r5 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=1310 dst=r1 src=r10 offset=0 imm=0
#line 174 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1311 dst=r1 src=r0 offset=0 imm=-64
#line 174 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1312 dst=r2 src=r0 offset=0 imm=55
#line 174 "sample/map.c"
    r2 = IMMEDIATE(55);
    // EBPF_OP_MOV64_IMM pc=1313 dst=r4 src=r0 offset=0 imm=-29
#line 174 "sample/map.c"
    r4 = IMMEDIATE(-29);
    // EBPF_OP_JA pc=1314 dst=r0 src=r0 offset=-167 imm=0
#line 174 "sample/map.c"
    goto label_72;
label_75:
    // EBPF_OP_STXW pc=1315 dst=r10 src=r7 offset=-4 imm=0
#line 175 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=1316 dst=r2 src=r10 offset=0 imm=0
#line 175 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1317 dst=r2 src=r0 offset=0 imm=-4
#line 175 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1318 dst=r1 src=r0 offset=0 imm=0
#line 175 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_MOV64_IMM pc=1320 dst=r3 src=r0 offset=0 imm=2
#line 175 "sample/map.c"
    r3 = IMMEDIATE(2);
    // EBPF_OP_CALL pc=1321 dst=r0 src=r0 offset=0 imm=16
#line 175 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 175 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 175 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 175 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1322 dst=r6 src=r0 offset=0 imm=0
#line 175 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1323 dst=r5 src=r6 offset=0 imm=0
#line 175 "sample/map.c"
    r5 = r6;
    // EBPF_OP_LSH64_IMM pc=1324 dst=r5 src=r0 offset=0 imm=32
#line 175 "sample/map.c"
    r5 <<= IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=1325 dst=r1 src=r5 offset=0 imm=0
#line 175 "sample/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=1326 dst=r1 src=r0 offset=0 imm=32
#line 175 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=1327 dst=r1 src=r0 offset=26 imm=0
#line 175 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 175 "sample/map.c"
        goto label_76;
        // EBPF_OP_MOV64_IMM pc=1328 dst=r1 src=r0 offset=0 imm=25637
#line 175 "sample/map.c"
    r1 = IMMEDIATE(25637);
    // EBPF_OP_STXH pc=1329 dst=r10 src=r1 offset=-12 imm=0
#line 175 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-12)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=1330 dst=r1 src=r0 offset=0 imm=543450478
#line 175 "sample/map.c"
    r1 = IMMEDIATE(543450478);
    // EBPF_OP_STXW pc=1331 dst=r10 src=r1 offset=-16 imm=0
#line 175 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=1332 dst=r1 src=r0 offset=0 imm=1914725413
#line 175 "sample/map.c"
    r1 = (uint64_t)8247626271654175781;
    // EBPF_OP_STXDW pc=1334 dst=r10 src=r1 offset=-24 imm=0
#line 175 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1335 dst=r1 src=r0 offset=0 imm=1667592312
#line 175 "sample/map.c"
    r1 = (uint64_t)2334102057442963576;
    // EBPF_OP_STXDW pc=1337 dst=r10 src=r1 offset=-32 imm=0
#line 175 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1338 dst=r1 src=r0 offset=0 imm=543649385
#line 175 "sample/map.c"
    r1 = (uint64_t)7286934307705679465;
    // EBPF_OP_STXDW pc=1340 dst=r10 src=r1 offset=-40 imm=0
#line 175 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1341 dst=r1 src=r0 offset=0 imm=1852383341
#line 175 "sample/map.c"
    r1 = (uint64_t)8390880602192683117;
    // EBPF_OP_STXDW pc=1343 dst=r10 src=r1 offset=-48 imm=0
#line 175 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1344 dst=r1 src=r0 offset=0 imm=1752397168
#line 175 "sample/map.c"
    r1 = (uint64_t)7308327755764168048;
    // EBPF_OP_STXDW pc=1346 dst=r10 src=r1 offset=-56 imm=0
#line 175 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1347 dst=r1 src=r0 offset=0 imm=1600548962
#line 175 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1349 dst=r10 src=r1 offset=-64 imm=0
#line 175 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_IMM pc=1350 dst=r1 src=r0 offset=0 imm=0
#line 175 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=1351 dst=r10 src=r1 offset=-10 imm=0
#line 175 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-10)) = (uint8_t)r1;
    // EBPF_OP_LDXW pc=1352 dst=r3 src=r10 offset=-4 imm=0
#line 175 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JA pc=1353 dst=r0 src=r0 offset=-211 imm=0
#line 175 "sample/map.c"
    goto label_71;
label_76:
    // EBPF_OP_MOV64_IMM pc=1354 dst=r1 src=r0 offset=0 imm=0
#line 175 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1355 dst=r10 src=r1 offset=-4 imm=0
#line 177 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1356 dst=r2 src=r10 offset=0 imm=0
#line 177 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1357 dst=r2 src=r0 offset=0 imm=-4
#line 177 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1358 dst=r1 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=1360 dst=r0 src=r0 offset=0 imm=18
#line 177 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 177 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 177 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 177 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1361 dst=r6 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1362 dst=r4 src=r6 offset=0 imm=0
#line 177 "sample/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=1363 dst=r4 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r4 <<= IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=1364 dst=r1 src=r4 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=1365 dst=r1 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=1366 dst=r1 src=r0 offset=27 imm=0
#line 177 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 177 "sample/map.c"
        goto label_78;
        // EBPF_OP_MOV64_IMM pc=1367 dst=r1 src=r0 offset=0 imm=100
#line 177 "sample/map.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXH pc=1368 dst=r10 src=r1 offset=-16 imm=0
#line 177 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=1369 dst=r1 src=r0 offset=0 imm=1852994932
#line 177 "sample/map.c"
    r1 = (uint64_t)2675248565465544052;
    // EBPF_OP_STXDW pc=1371 dst=r10 src=r1 offset=-24 imm=0
#line 177 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1372 dst=r1 src=r0 offset=0 imm=622883948
#line 177 "sample/map.c"
    r1 = (uint64_t)7309940759667438700;
    // EBPF_OP_STXDW pc=1374 dst=r10 src=r1 offset=-32 imm=0
#line 177 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1375 dst=r1 src=r0 offset=0 imm=543649385
#line 177 "sample/map.c"
    r1 = (uint64_t)8463219665603620457;
    // EBPF_OP_STXDW pc=1377 dst=r10 src=r1 offset=-40 imm=0
#line 177 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1378 dst=r1 src=r0 offset=0 imm=2019893357
#line 177 "sample/map.c"
    r1 = (uint64_t)8386658464824631405;
    // EBPF_OP_STXDW pc=1380 dst=r10 src=r1 offset=-48 imm=0
#line 177 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1381 dst=r1 src=r0 offset=0 imm=1801807216
#line 177 "sample/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=1383 dst=r10 src=r1 offset=-56 imm=0
#line 177 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1384 dst=r1 src=r0 offset=0 imm=1600548962
#line 177 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1386 dst=r10 src=r1 offset=-64 imm=0
#line 177 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_ARSH64_IMM pc=1387 dst=r4 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r4 = (int64_t)r4 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=1388 dst=r1 src=r10 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1389 dst=r1 src=r0 offset=0 imm=-64
#line 177 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1390 dst=r2 src=r0 offset=0 imm=50
#line 177 "sample/map.c"
    r2 = IMMEDIATE(50);
label_77:
    // EBPF_OP_MOV64_IMM pc=1391 dst=r3 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1392 dst=r0 src=r0 offset=0 imm=14
#line 177 "sample/map.c"
    r0 = test_maps_helpers[7].address
#line 177 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 177 "sample/map.c"
    if ((test_maps_helpers[7].tail_call) && (r0 == 0))
#line 177 "sample/map.c"
        return 0;
        // EBPF_OP_JA pc=1393 dst=r0 src=r0 offset=-373 imm=0
#line 177 "sample/map.c"
    goto label_64;
label_78:
    // EBPF_OP_LDXW pc=1394 dst=r3 src=r10 offset=-4 imm=0
#line 177 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1395 dst=r3 src=r0 offset=22 imm=1
#line 177 "sample/map.c"
    if (r3 == IMMEDIATE(1))
#line 177 "sample/map.c"
        goto label_79;
        // EBPF_OP_MOV64_IMM pc=1396 dst=r1 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=1397 dst=r10 src=r1 offset=-24 imm=0
#line 177 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint8_t)r1;
    // EBPF_OP_LDDW pc=1398 dst=r1 src=r0 offset=0 imm=1852404835
#line 177 "sample/map.c"
    r1 = (uint64_t)7216209606537213027;
    // EBPF_OP_STXDW pc=1400 dst=r10 src=r1 offset=-32 imm=0
#line 177 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1401 dst=r1 src=r0 offset=0 imm=543434016
#line 177 "sample/map.c"
    r1 = (uint64_t)7309474570952779040;
    // EBPF_OP_STXDW pc=1403 dst=r10 src=r1 offset=-40 imm=0
#line 177 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1404 dst=r1 src=r0 offset=0 imm=1701978221
#line 177 "sample/map.c"
    r1 = (uint64_t)7958552634295722093;
    // EBPF_OP_STXDW pc=1406 dst=r10 src=r1 offset=-48 imm=0
#line 177 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1407 dst=r1 src=r0 offset=0 imm=1801807216
#line 177 "sample/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=1409 dst=r10 src=r1 offset=-56 imm=0
#line 177 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1410 dst=r1 src=r0 offset=0 imm=1600548962
#line 177 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1412 dst=r10 src=r1 offset=-64 imm=0
#line 177 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1413 dst=r1 src=r10 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1414 dst=r1 src=r0 offset=0 imm=-64
#line 177 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1415 dst=r2 src=r0 offset=0 imm=41
#line 177 "sample/map.c"
    r2 = IMMEDIATE(41);
    // EBPF_OP_MOV64_IMM pc=1416 dst=r4 src=r0 offset=0 imm=1
#line 177 "sample/map.c"
    r4 = IMMEDIATE(1);
    // EBPF_OP_JA pc=1417 dst=r0 src=r0 offset=-400 imm=0
#line 177 "sample/map.c"
    goto label_63;
label_79:
    // EBPF_OP_MOV64_IMM pc=1418 dst=r7 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1419 dst=r10 src=r7 offset=-4 imm=0
#line 180 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=1420 dst=r2 src=r10 offset=0 imm=0
#line 180 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1421 dst=r2 src=r0 offset=0 imm=-4
#line 180 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1422 dst=r1 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=1424 dst=r0 src=r0 offset=0 imm=17
#line 180 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 180 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 180 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 180 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1425 dst=r6 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1426 dst=r1 src=r6 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=1427 dst=r1 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1428 dst=r1 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=1429 dst=r1 src=r0 offset=26 imm=0
#line 180 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 180 "sample/map.c"
        goto label_81;
label_80:
    // EBPF_OP_LDDW pc=1430 dst=r1 src=r0 offset=0 imm=1701737077
#line 180 "sample/map.c"
    r1 = (uint64_t)7216209593501643381;
    // EBPF_OP_STXDW pc=1432 dst=r10 src=r1 offset=-24 imm=0
#line 180 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1433 dst=r1 src=r0 offset=0 imm=1680154740
#line 180 "sample/map.c"
    r1 = (uint64_t)8387235364492091508;
    // EBPF_OP_STXDW pc=1435 dst=r10 src=r1 offset=-32 imm=0
#line 180 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1436 dst=r1 src=r0 offset=0 imm=1914726254
#line 180 "sample/map.c"
    r1 = (uint64_t)7815279607914981230;
    // EBPF_OP_STXDW pc=1438 dst=r10 src=r1 offset=-40 imm=0
#line 180 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1439 dst=r1 src=r0 offset=0 imm=1886938400
#line 180 "sample/map.c"
    r1 = (uint64_t)7598807758610654496;
    // EBPF_OP_STXDW pc=1441 dst=r10 src=r1 offset=-48 imm=0
#line 180 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1442 dst=r1 src=r0 offset=0 imm=1601204080
#line 180 "sample/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=1444 dst=r10 src=r1 offset=-56 imm=0
#line 180 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1445 dst=r1 src=r0 offset=0 imm=1600548962
#line 180 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1447 dst=r10 src=r1 offset=-64 imm=0
#line 180 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_STXB pc=1448 dst=r10 src=r7 offset=-16 imm=0
#line 180 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint8_t)r7;
    // EBPF_OP_MOV64_REG pc=1449 dst=r4 src=r6 offset=0 imm=0
#line 180 "sample/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=1450 dst=r4 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r4 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=1451 dst=r4 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r4 = (int64_t)r4 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=1452 dst=r1 src=r10 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1453 dst=r1 src=r0 offset=0 imm=-64
#line 180 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1454 dst=r2 src=r0 offset=0 imm=49
#line 180 "sample/map.c"
    r2 = IMMEDIATE(49);
    // EBPF_OP_JA pc=1455 dst=r0 src=r0 offset=-65 imm=0
#line 180 "sample/map.c"
    goto label_77;
label_81:
    // EBPF_OP_MOV64_IMM pc=1456 dst=r4 src=r0 offset=0 imm=1
#line 180 "sample/map.c"
    r4 = IMMEDIATE(1);
    // EBPF_OP_LDXW pc=1457 dst=r3 src=r10 offset=-4 imm=0
#line 180 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1458 dst=r3 src=r0 offset=19 imm=1
#line 180 "sample/map.c"
    if (r3 == IMMEDIATE(1))
#line 180 "sample/map.c"
        goto label_83;
label_82:
    // EBPF_OP_LDDW pc=1459 dst=r1 src=r0 offset=0 imm=1735289204
#line 180 "sample/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=1461 dst=r10 src=r1 offset=-32 imm=0
#line 180 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1462 dst=r1 src=r0 offset=0 imm=1696621605
#line 180 "sample/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=1464 dst=r10 src=r1 offset=-40 imm=0
#line 180 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1465 dst=r1 src=r0 offset=0 imm=1952805408
#line 180 "sample/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=1467 dst=r10 src=r1 offset=-48 imm=0
#line 180 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1468 dst=r1 src=r0 offset=0 imm=1601204080
#line 180 "sample/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=1470 dst=r10 src=r1 offset=-56 imm=0
#line 180 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1471 dst=r1 src=r0 offset=0 imm=1600548962
#line 180 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1473 dst=r10 src=r1 offset=-64 imm=0
#line 180 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1474 dst=r1 src=r10 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1475 dst=r1 src=r0 offset=0 imm=-64
#line 180 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1476 dst=r2 src=r0 offset=0 imm=40
#line 180 "sample/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_JA pc=1477 dst=r0 src=r0 offset=-460 imm=0
#line 180 "sample/map.c"
    goto label_63;
label_83:
    // EBPF_OP_MOV64_IMM pc=1478 dst=r1 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1479 dst=r10 src=r1 offset=-4 imm=0
#line 180 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1480 dst=r2 src=r10 offset=0 imm=0
#line 180 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1481 dst=r2 src=r0 offset=0 imm=-4
#line 180 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1482 dst=r1 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=1484 dst=r0 src=r0 offset=0 imm=17
#line 180 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 180 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 180 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 180 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1485 dst=r6 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1486 dst=r1 src=r6 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=1487 dst=r1 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1488 dst=r1 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=1489 dst=r1 src=r0 offset=1 imm=0
#line 180 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 180 "sample/map.c"
        goto label_84;
        // EBPF_OP_JA pc=1490 dst=r0 src=r0 offset=-61 imm=0
#line 180 "sample/map.c"
    goto label_80;
label_84:
    // EBPF_OP_MOV64_IMM pc=1491 dst=r4 src=r0 offset=0 imm=2
#line 180 "sample/map.c"
    r4 = IMMEDIATE(2);
    // EBPF_OP_LDXW pc=1492 dst=r3 src=r10 offset=-4 imm=0
#line 180 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=1493 dst=r3 src=r0 offset=-35 imm=2
#line 180 "sample/map.c"
    if (r3 != IMMEDIATE(2))
#line 180 "sample/map.c"
        goto label_82;
        // EBPF_OP_MOV64_IMM pc=1494 dst=r1 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1495 dst=r10 src=r1 offset=-4 imm=0
#line 180 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1496 dst=r2 src=r10 offset=0 imm=0
#line 180 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1497 dst=r2 src=r0 offset=0 imm=-4
#line 180 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1498 dst=r1 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=1500 dst=r0 src=r0 offset=0 imm=17
#line 180 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 180 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 180 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 180 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1501 dst=r6 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1502 dst=r1 src=r6 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=1503 dst=r1 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1504 dst=r1 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1505 dst=r1 src=r0 offset=-76 imm=0
#line 180 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 180 "sample/map.c"
        goto label_80;
        // EBPF_OP_MOV64_IMM pc=1506 dst=r4 src=r0 offset=0 imm=3
#line 180 "sample/map.c"
    r4 = IMMEDIATE(3);
    // EBPF_OP_LDXW pc=1507 dst=r3 src=r10 offset=-4 imm=0
#line 180 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=1508 dst=r3 src=r0 offset=-50 imm=3
#line 180 "sample/map.c"
    if (r3 != IMMEDIATE(3))
#line 180 "sample/map.c"
        goto label_82;
        // EBPF_OP_MOV64_IMM pc=1509 dst=r1 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1510 dst=r10 src=r1 offset=-4 imm=0
#line 180 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1511 dst=r2 src=r10 offset=0 imm=0
#line 180 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1512 dst=r2 src=r0 offset=0 imm=-4
#line 180 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1513 dst=r1 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=1515 dst=r0 src=r0 offset=0 imm=17
#line 180 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 180 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 180 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 180 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1516 dst=r6 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1517 dst=r1 src=r6 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=1518 dst=r1 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1519 dst=r1 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1520 dst=r1 src=r0 offset=-91 imm=0
#line 180 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 180 "sample/map.c"
        goto label_80;
        // EBPF_OP_MOV64_IMM pc=1521 dst=r4 src=r0 offset=0 imm=4
#line 180 "sample/map.c"
    r4 = IMMEDIATE(4);
    // EBPF_OP_LDXW pc=1522 dst=r3 src=r10 offset=-4 imm=0
#line 180 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=1523 dst=r3 src=r0 offset=-65 imm=4
#line 180 "sample/map.c"
    if (r3 != IMMEDIATE(4))
#line 180 "sample/map.c"
        goto label_82;
        // EBPF_OP_MOV64_IMM pc=1524 dst=r1 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1525 dst=r10 src=r1 offset=-4 imm=0
#line 180 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1526 dst=r2 src=r10 offset=0 imm=0
#line 180 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1527 dst=r2 src=r0 offset=0 imm=-4
#line 180 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1528 dst=r1 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=1530 dst=r0 src=r0 offset=0 imm=17
#line 180 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 180 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 180 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 180 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1531 dst=r6 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1532 dst=r1 src=r6 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=1533 dst=r1 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1534 dst=r1 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1535 dst=r1 src=r0 offset=-106 imm=0
#line 180 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 180 "sample/map.c"
        goto label_80;
        // EBPF_OP_MOV64_IMM pc=1536 dst=r4 src=r0 offset=0 imm=5
#line 180 "sample/map.c"
    r4 = IMMEDIATE(5);
    // EBPF_OP_LDXW pc=1537 dst=r3 src=r10 offset=-4 imm=0
#line 180 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=1538 dst=r3 src=r0 offset=-80 imm=5
#line 180 "sample/map.c"
    if (r3 != IMMEDIATE(5))
#line 180 "sample/map.c"
        goto label_82;
        // EBPF_OP_MOV64_IMM pc=1539 dst=r1 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1540 dst=r10 src=r1 offset=-4 imm=0
#line 180 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1541 dst=r2 src=r10 offset=0 imm=0
#line 180 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1542 dst=r2 src=r0 offset=0 imm=-4
#line 180 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1543 dst=r1 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=1545 dst=r0 src=r0 offset=0 imm=17
#line 180 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 180 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 180 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 180 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1546 dst=r6 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1547 dst=r1 src=r6 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=1548 dst=r1 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1549 dst=r1 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1550 dst=r1 src=r0 offset=-121 imm=0
#line 180 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 180 "sample/map.c"
        goto label_80;
        // EBPF_OP_MOV64_IMM pc=1551 dst=r4 src=r0 offset=0 imm=6
#line 180 "sample/map.c"
    r4 = IMMEDIATE(6);
    // EBPF_OP_LDXW pc=1552 dst=r3 src=r10 offset=-4 imm=0
#line 180 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=1553 dst=r3 src=r0 offset=-95 imm=6
#line 180 "sample/map.c"
    if (r3 != IMMEDIATE(6))
#line 180 "sample/map.c"
        goto label_82;
        // EBPF_OP_MOV64_IMM pc=1554 dst=r1 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1555 dst=r10 src=r1 offset=-4 imm=0
#line 180 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1556 dst=r2 src=r10 offset=0 imm=0
#line 180 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1557 dst=r2 src=r0 offset=0 imm=-4
#line 180 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1558 dst=r1 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=1560 dst=r0 src=r0 offset=0 imm=17
#line 180 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 180 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 180 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 180 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1561 dst=r6 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1562 dst=r1 src=r6 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=1563 dst=r1 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1564 dst=r1 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1565 dst=r1 src=r0 offset=-136 imm=0
#line 180 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 180 "sample/map.c"
        goto label_80;
        // EBPF_OP_MOV64_IMM pc=1566 dst=r4 src=r0 offset=0 imm=7
#line 180 "sample/map.c"
    r4 = IMMEDIATE(7);
    // EBPF_OP_LDXW pc=1567 dst=r3 src=r10 offset=-4 imm=0
#line 180 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=1568 dst=r3 src=r0 offset=-110 imm=7
#line 180 "sample/map.c"
    if (r3 != IMMEDIATE(7))
#line 180 "sample/map.c"
        goto label_82;
        // EBPF_OP_MOV64_IMM pc=1569 dst=r1 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1570 dst=r10 src=r1 offset=-4 imm=0
#line 180 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1571 dst=r2 src=r10 offset=0 imm=0
#line 180 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1572 dst=r2 src=r0 offset=0 imm=-4
#line 180 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1573 dst=r1 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=1575 dst=r0 src=r0 offset=0 imm=17
#line 180 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 180 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 180 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 180 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1576 dst=r6 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1577 dst=r1 src=r6 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=1578 dst=r1 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1579 dst=r1 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1580 dst=r1 src=r0 offset=-151 imm=0
#line 180 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 180 "sample/map.c"
        goto label_80;
        // EBPF_OP_MOV64_IMM pc=1581 dst=r4 src=r0 offset=0 imm=8
#line 180 "sample/map.c"
    r4 = IMMEDIATE(8);
    // EBPF_OP_LDXW pc=1582 dst=r3 src=r10 offset=-4 imm=0
#line 180 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=1583 dst=r3 src=r0 offset=-125 imm=8
#line 180 "sample/map.c"
    if (r3 != IMMEDIATE(8))
#line 180 "sample/map.c"
        goto label_82;
        // EBPF_OP_MOV64_IMM pc=1584 dst=r1 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1585 dst=r10 src=r1 offset=-4 imm=0
#line 180 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1586 dst=r2 src=r10 offset=0 imm=0
#line 180 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1587 dst=r2 src=r0 offset=0 imm=-4
#line 180 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1588 dst=r1 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=1590 dst=r0 src=r0 offset=0 imm=17
#line 180 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 180 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 180 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 180 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1591 dst=r6 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1592 dst=r1 src=r6 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=1593 dst=r1 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1594 dst=r1 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1595 dst=r1 src=r0 offset=-166 imm=0
#line 180 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 180 "sample/map.c"
        goto label_80;
        // EBPF_OP_MOV64_IMM pc=1596 dst=r4 src=r0 offset=0 imm=9
#line 180 "sample/map.c"
    r4 = IMMEDIATE(9);
    // EBPF_OP_LDXW pc=1597 dst=r3 src=r10 offset=-4 imm=0
#line 180 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=1598 dst=r3 src=r0 offset=-140 imm=9
#line 180 "sample/map.c"
    if (r3 != IMMEDIATE(9))
#line 180 "sample/map.c"
        goto label_82;
        // EBPF_OP_MOV64_IMM pc=1599 dst=r1 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1600 dst=r10 src=r1 offset=-4 imm=0
#line 180 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1601 dst=r2 src=r10 offset=0 imm=0
#line 180 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1602 dst=r2 src=r0 offset=0 imm=-4
#line 180 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1603 dst=r1 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=1605 dst=r0 src=r0 offset=0 imm=17
#line 180 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 180 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 180 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 180 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1606 dst=r6 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1607 dst=r1 src=r6 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = r6;
    // EBPF_OP_LSH64_IMM pc=1608 dst=r1 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1609 dst=r1 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1610 dst=r1 src=r0 offset=-181 imm=0
#line 180 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 180 "sample/map.c"
        goto label_80;
        // EBPF_OP_MOV64_IMM pc=1611 dst=r4 src=r0 offset=0 imm=10
#line 180 "sample/map.c"
    r4 = IMMEDIATE(10);
    // EBPF_OP_LDXW pc=1612 dst=r3 src=r10 offset=-4 imm=0
#line 180 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=1613 dst=r3 src=r0 offset=-155 imm=10
#line 180 "sample/map.c"
    if (r3 != IMMEDIATE(10))
#line 180 "sample/map.c"
        goto label_82;
        // EBPF_OP_MOV64_IMM pc=1614 dst=r1 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1615 dst=r10 src=r1 offset=-4 imm=0
#line 183 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1616 dst=r2 src=r10 offset=0 imm=0
#line 183 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1617 dst=r2 src=r0 offset=0 imm=-4
#line 183 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1618 dst=r1 src=r0 offset=0 imm=0
#line 183 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=1620 dst=r0 src=r0 offset=0 imm=18
#line 183 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 183 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 183 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 183 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1621 dst=r6 src=r0 offset=0 imm=0
#line 183 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1622 dst=r4 src=r6 offset=0 imm=0
#line 183 "sample/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=1623 dst=r4 src=r0 offset=0 imm=32
#line 183 "sample/map.c"
    r4 <<= IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=1624 dst=r1 src=r4 offset=0 imm=0
#line 183 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=1625 dst=r1 src=r0 offset=0 imm=32
#line 183 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_LDDW pc=1626 dst=r2 src=r0 offset=0 imm=-7
#line 183 "sample/map.c"
    r2 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=1628 dst=r1 src=r2 offset=1 imm=0
#line 183 "sample/map.c"
    if (r1 == r2)
#line 183 "sample/map.c"
        goto label_85;
        // EBPF_OP_JA pc=1629 dst=r0 src=r0 offset=-740 imm=0
#line 183 "sample/map.c"
    goto label_55;
label_85:
    // EBPF_OP_LDXW pc=1630 dst=r3 src=r10 offset=-4 imm=0
#line 183 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1631 dst=r3 src=r0 offset=1 imm=0
#line 183 "sample/map.c"
    if (r3 == IMMEDIATE(0))
#line 183 "sample/map.c"
        goto label_86;
        // EBPF_OP_JA pc=1632 dst=r0 src=r0 offset=-636 imm=0
#line 183 "sample/map.c"
    goto label_61;
label_86:
    // EBPF_OP_MOV64_IMM pc=1633 dst=r7 src=r0 offset=0 imm=0
#line 183 "sample/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1634 dst=r10 src=r7 offset=-4 imm=0
#line 184 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=1635 dst=r2 src=r10 offset=0 imm=0
#line 184 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1636 dst=r2 src=r0 offset=0 imm=-4
#line 184 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1637 dst=r1 src=r0 offset=0 imm=0
#line 184 "sample/map.c"
    r1 = POINTER(_maps[6].address);
    // EBPF_OP_CALL pc=1639 dst=r0 src=r0 offset=0 imm=17
#line 184 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 184 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 184 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 184 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1640 dst=r6 src=r0 offset=0 imm=0
#line 184 "sample/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1641 dst=r4 src=r6 offset=0 imm=0
#line 184 "sample/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=1642 dst=r4 src=r0 offset=0 imm=32
#line 184 "sample/map.c"
    r4 <<= IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=1643 dst=r1 src=r4 offset=0 imm=0
#line 184 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=1644 dst=r1 src=r0 offset=0 imm=32
#line 184 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_LDDW pc=1645 dst=r2 src=r0 offset=0 imm=-7
#line 184 "sample/map.c"
    r2 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=1647 dst=r1 src=r2 offset=1 imm=0
#line 184 "sample/map.c"
    if (r1 == r2)
#line 184 "sample/map.c"
        goto label_87;
        // EBPF_OP_JA pc=1648 dst=r0 src=r0 offset=-590 imm=0
#line 184 "sample/map.c"
    goto label_66;
label_87:
    // EBPF_OP_LDXW pc=1649 dst=r3 src=r10 offset=-4 imm=0
#line 184 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1650 dst=r3 src=r0 offset=1 imm=0
#line 184 "sample/map.c"
    if (r3 == IMMEDIATE(0))
#line 184 "sample/map.c"
        goto label_88;
        // EBPF_OP_JA pc=1651 dst=r0 src=r0 offset=-567 imm=0
#line 184 "sample/map.c"
    goto label_68;
label_88:
    // EBPF_OP_MOV64_IMM pc=1652 dst=r1 src=r0 offset=0 imm=0
#line 184 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1653 dst=r10 src=r1 offset=-4 imm=0
#line 167 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1654 dst=r2 src=r10 offset=0 imm=0
#line 167 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1655 dst=r2 src=r0 offset=0 imm=-4
#line 167 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1656 dst=r1 src=r0 offset=0 imm=0
#line 167 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=1658 dst=r0 src=r0 offset=0 imm=18
#line 167 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 167 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 167 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 167 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1659 dst=r7 src=r0 offset=0 imm=0
#line 167 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1660 dst=r4 src=r7 offset=0 imm=0
#line 167 "sample/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=1661 dst=r4 src=r0 offset=0 imm=32
#line 167 "sample/map.c"
    r4 <<= IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=1662 dst=r1 src=r4 offset=0 imm=0
#line 167 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=1663 dst=r1 src=r0 offset=0 imm=32
#line 167 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_LDDW pc=1664 dst=r2 src=r0 offset=0 imm=-7
#line 167 "sample/map.c"
    r2 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=1666 dst=r1 src=r2 offset=27 imm=0
#line 167 "sample/map.c"
    if (r1 == r2)
#line 167 "sample/map.c"
        goto label_91;
label_89:
    // EBPF_OP_MOV64_IMM pc=1667 dst=r1 src=r0 offset=0 imm=100
#line 167 "sample/map.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXH pc=1668 dst=r10 src=r1 offset=-16 imm=0
#line 167 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=1669 dst=r1 src=r0 offset=0 imm=1852994932
#line 167 "sample/map.c"
    r1 = (uint64_t)2675248565465544052;
    // EBPF_OP_STXDW pc=1671 dst=r10 src=r1 offset=-24 imm=0
#line 167 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1672 dst=r1 src=r0 offset=0 imm=622883948
#line 167 "sample/map.c"
    r1 = (uint64_t)7309940759667438700;
    // EBPF_OP_STXDW pc=1674 dst=r10 src=r1 offset=-32 imm=0
#line 167 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1675 dst=r1 src=r0 offset=0 imm=543649385
#line 167 "sample/map.c"
    r1 = (uint64_t)8463219665603620457;
    // EBPF_OP_STXDW pc=1677 dst=r10 src=r1 offset=-40 imm=0
#line 167 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1678 dst=r1 src=r0 offset=0 imm=2019893357
#line 167 "sample/map.c"
    r1 = (uint64_t)8386658464824631405;
    // EBPF_OP_STXDW pc=1680 dst=r10 src=r1 offset=-48 imm=0
#line 167 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1681 dst=r1 src=r0 offset=0 imm=1801807216
#line 167 "sample/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=1683 dst=r10 src=r1 offset=-56 imm=0
#line 167 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1684 dst=r1 src=r0 offset=0 imm=1600548962
#line 167 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1686 dst=r10 src=r1 offset=-64 imm=0
#line 167 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_ARSH64_IMM pc=1687 dst=r4 src=r0 offset=0 imm=32
#line 167 "sample/map.c"
    r4 = (int64_t)r4 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=1688 dst=r1 src=r10 offset=0 imm=0
#line 167 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1689 dst=r1 src=r0 offset=0 imm=-64
#line 167 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1690 dst=r2 src=r0 offset=0 imm=50
#line 167 "sample/map.c"
    r2 = IMMEDIATE(50);
label_90:
    // EBPF_OP_MOV64_IMM pc=1691 dst=r3 src=r0 offset=0 imm=-7
#line 167 "sample/map.c"
    r3 = IMMEDIATE(-7);
    // EBPF_OP_CALL pc=1692 dst=r0 src=r0 offset=0 imm=14
#line 167 "sample/map.c"
    r0 = test_maps_helpers[7].address
#line 167 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 167 "sample/map.c"
    if ((test_maps_helpers[7].tail_call) && (r0 == 0))
#line 167 "sample/map.c"
        return 0;
        // EBPF_OP_JA pc=1693 dst=r0 src=r0 offset=26 imm=0
#line 167 "sample/map.c"
    goto label_95;
label_91:
    // EBPF_OP_LDXW pc=1694 dst=r3 src=r10 offset=-4 imm=0
#line 167 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1695 dst=r3 src=r0 offset=50 imm=0
#line 167 "sample/map.c"
    if (r3 == IMMEDIATE(0))
#line 167 "sample/map.c"
        goto label_96;
label_92:
    // EBPF_OP_LDDW pc=1696 dst=r1 src=r0 offset=0 imm=1852404835
#line 167 "sample/map.c"
    r1 = (uint64_t)7216209606537213027;
    // EBPF_OP_STXDW pc=1698 dst=r10 src=r1 offset=-32 imm=0
#line 167 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1699 dst=r1 src=r0 offset=0 imm=543434016
#line 167 "sample/map.c"
    r1 = (uint64_t)7309474570952779040;
    // EBPF_OP_STXDW pc=1701 dst=r10 src=r1 offset=-40 imm=0
#line 167 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1702 dst=r1 src=r0 offset=0 imm=1701978221
#line 167 "sample/map.c"
    r1 = (uint64_t)7958552634295722093;
    // EBPF_OP_STXDW pc=1704 dst=r10 src=r1 offset=-48 imm=0
#line 167 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1705 dst=r1 src=r0 offset=0 imm=1801807216
#line 167 "sample/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=1707 dst=r10 src=r1 offset=-56 imm=0
#line 167 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1708 dst=r1 src=r0 offset=0 imm=1600548962
#line 167 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1710 dst=r10 src=r1 offset=-64 imm=0
#line 167 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_IMM pc=1711 dst=r1 src=r0 offset=0 imm=0
#line 167 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=1712 dst=r10 src=r1 offset=-24 imm=0
#line 167 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint8_t)r1;
    // EBPF_OP_MOV64_REG pc=1713 dst=r1 src=r10 offset=0 imm=0
#line 167 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1714 dst=r1 src=r0 offset=0 imm=-64
#line 167 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1715 dst=r2 src=r0 offset=0 imm=41
#line 167 "sample/map.c"
    r2 = IMMEDIATE(41);
label_93:
    // EBPF_OP_MOV64_IMM pc=1716 dst=r4 src=r0 offset=0 imm=0
#line 167 "sample/map.c"
    r4 = IMMEDIATE(0);
label_94:
    // EBPF_OP_CALL pc=1717 dst=r0 src=r0 offset=0 imm=14
#line 167 "sample/map.c"
    r0 = test_maps_helpers[7].address
#line 167 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 167 "sample/map.c"
    if ((test_maps_helpers[7].tail_call) && (r0 == 0))
#line 167 "sample/map.c"
        return 0;
        // EBPF_OP_LDDW pc=1718 dst=r7 src=r0 offset=0 imm=-1
#line 167 "sample/map.c"
    r7 = (uint64_t)4294967295;
label_95:
    // EBPF_OP_MOV64_IMM pc=1720 dst=r6 src=r0 offset=0 imm=0
#line 167 "sample/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_MOV64_REG pc=1721 dst=r3 src=r7 offset=0 imm=0
#line 203 "sample/map.c"
    r3 = r7;
    // EBPF_OP_LSH64_IMM pc=1722 dst=r3 src=r0 offset=0 imm=32
#line 203 "sample/map.c"
    r3 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=1723 dst=r3 src=r0 offset=0 imm=32
#line 203 "sample/map.c"
    r3 = (int64_t)r3 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_JSGT_IMM pc=1724 dst=r3 src=r0 offset=-1623 imm=-1
#line 203 "sample/map.c"
    if ((int64_t)r3 > (int64_t)IMMEDIATE(-1))
#line 203 "sample/map.c"
        goto label_8;
        // EBPF_OP_LDDW pc=1725 dst=r1 src=r0 offset=0 imm=1684369010
#line 203 "sample/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=1727 dst=r10 src=r1 offset=-32 imm=0
#line 203 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1728 dst=r1 src=r0 offset=0 imm=541803329
#line 203 "sample/map.c"
    r1 = (uint64_t)8463501140578485057;
    // EBPF_OP_STXDW pc=1730 dst=r10 src=r1 offset=-40 imm=0
#line 203 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1731 dst=r1 src=r0 offset=0 imm=1634541682
#line 203 "sample/map.c"
    r1 = (uint64_t)6076235989295898738;
    // EBPF_OP_STXDW pc=1733 dst=r10 src=r1 offset=-48 imm=0
#line 203 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1734 dst=r1 src=r0 offset=0 imm=1330667336
#line 203 "sample/map.c"
    r1 = (uint64_t)8027138915134627656;
    // EBPF_OP_STXDW pc=1736 dst=r10 src=r1 offset=-56 imm=0
#line 203 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1737 dst=r1 src=r0 offset=0 imm=1953719636
#line 203 "sample/map.c"
    r1 = (uint64_t)6004793778491319636;
    // EBPF_OP_STXDW pc=1739 dst=r10 src=r1 offset=-64 imm=0
#line 203 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1740 dst=r1 src=r10 offset=0 imm=0
#line 203 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1741 dst=r1 src=r0 offset=0 imm=-64
#line 203 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1742 dst=r2 src=r0 offset=0 imm=40
#line 203 "sample/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_CALL pc=1743 dst=r0 src=r0 offset=0 imm=13
#line 203 "sample/map.c"
    r0 = test_maps_helpers[4].address
#line 203 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 203 "sample/map.c"
    if ((test_maps_helpers[4].tail_call) && (r0 == 0))
#line 203 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1744 dst=r6 src=r7 offset=0 imm=0
#line 203 "sample/map.c"
    r6 = r7;
    // EBPF_OP_JA pc=1745 dst=r0 src=r0 offset=-1644 imm=0
#line 203 "sample/map.c"
    goto label_8;
label_96:
    // EBPF_OP_MOV64_IMM pc=1746 dst=r6 src=r0 offset=0 imm=0
#line 203 "sample/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1747 dst=r10 src=r6 offset=-4 imm=0
#line 168 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=1748 dst=r2 src=r10 offset=0 imm=0
#line 168 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1749 dst=r2 src=r0 offset=0 imm=-4
#line 168 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1750 dst=r1 src=r0 offset=0 imm=0
#line 168 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=1752 dst=r0 src=r0 offset=0 imm=17
#line 168 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 168 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 168 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 168 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1753 dst=r7 src=r0 offset=0 imm=0
#line 168 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1754 dst=r4 src=r7 offset=0 imm=0
#line 168 "sample/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=1755 dst=r4 src=r0 offset=0 imm=32
#line 168 "sample/map.c"
    r4 <<= IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=1756 dst=r1 src=r4 offset=0 imm=0
#line 168 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=1757 dst=r1 src=r0 offset=0 imm=32
#line 168 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_LDDW pc=1758 dst=r2 src=r0 offset=0 imm=-7
#line 168 "sample/map.c"
    r2 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=1760 dst=r1 src=r2 offset=24 imm=0
#line 168 "sample/map.c"
    if (r1 == r2)
#line 168 "sample/map.c"
        goto label_98;
label_97:
    // EBPF_OP_STXB pc=1761 dst=r10 src=r6 offset=-16 imm=0
#line 168 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint8_t)r6;
    // EBPF_OP_LDDW pc=1762 dst=r1 src=r0 offset=0 imm=1701737077
#line 168 "sample/map.c"
    r1 = (uint64_t)7216209593501643381;
    // EBPF_OP_STXDW pc=1764 dst=r10 src=r1 offset=-24 imm=0
#line 168 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1765 dst=r1 src=r0 offset=0 imm=1680154740
#line 168 "sample/map.c"
    r1 = (uint64_t)8387235364492091508;
    // EBPF_OP_STXDW pc=1767 dst=r10 src=r1 offset=-32 imm=0
#line 168 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1768 dst=r1 src=r0 offset=0 imm=1914726254
#line 168 "sample/map.c"
    r1 = (uint64_t)7815279607914981230;
    // EBPF_OP_STXDW pc=1770 dst=r10 src=r1 offset=-40 imm=0
#line 168 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1771 dst=r1 src=r0 offset=0 imm=1886938400
#line 168 "sample/map.c"
    r1 = (uint64_t)7598807758610654496;
    // EBPF_OP_STXDW pc=1773 dst=r10 src=r1 offset=-48 imm=0
#line 168 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1774 dst=r1 src=r0 offset=0 imm=1601204080
#line 168 "sample/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=1776 dst=r10 src=r1 offset=-56 imm=0
#line 168 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1777 dst=r1 src=r0 offset=0 imm=1600548962
#line 168 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1779 dst=r10 src=r1 offset=-64 imm=0
#line 168 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_ARSH64_IMM pc=1780 dst=r4 src=r0 offset=0 imm=32
#line 168 "sample/map.c"
    r4 = (int64_t)r4 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=1781 dst=r1 src=r10 offset=0 imm=0
#line 168 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1782 dst=r1 src=r0 offset=0 imm=-64
#line 168 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1783 dst=r2 src=r0 offset=0 imm=49
#line 168 "sample/map.c"
    r2 = IMMEDIATE(49);
    // EBPF_OP_JA pc=1784 dst=r0 src=r0 offset=-94 imm=0
#line 168 "sample/map.c"
    goto label_90;
label_98:
    // EBPF_OP_LDXW pc=1785 dst=r3 src=r10 offset=-4 imm=0
#line 168 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1786 dst=r3 src=r0 offset=19 imm=0
#line 168 "sample/map.c"
    if (r3 == IMMEDIATE(0))
#line 168 "sample/map.c"
        goto label_100;
label_99:
    // EBPF_OP_LDDW pc=1787 dst=r1 src=r0 offset=0 imm=1735289204
#line 168 "sample/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=1789 dst=r10 src=r1 offset=-32 imm=0
#line 168 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1790 dst=r1 src=r0 offset=0 imm=1696621605
#line 168 "sample/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=1792 dst=r10 src=r1 offset=-40 imm=0
#line 168 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1793 dst=r1 src=r0 offset=0 imm=1952805408
#line 168 "sample/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=1795 dst=r10 src=r1 offset=-48 imm=0
#line 168 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1796 dst=r1 src=r0 offset=0 imm=1601204080
#line 168 "sample/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=1798 dst=r10 src=r1 offset=-56 imm=0
#line 168 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1799 dst=r1 src=r0 offset=0 imm=1600548962
#line 168 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1801 dst=r10 src=r1 offset=-64 imm=0
#line 168 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1802 dst=r1 src=r10 offset=0 imm=0
#line 168 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1803 dst=r1 src=r0 offset=0 imm=-64
#line 168 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1804 dst=r2 src=r0 offset=0 imm=40
#line 168 "sample/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_JA pc=1805 dst=r0 src=r0 offset=-90 imm=0
#line 168 "sample/map.c"
    goto label_93;
label_100:
    // EBPF_OP_MOV64_IMM pc=1806 dst=r6 src=r0 offset=0 imm=0
#line 168 "sample/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1807 dst=r10 src=r6 offset=-4 imm=0
#line 171 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=1808 dst=r2 src=r10 offset=0 imm=0
#line 171 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1809 dst=r2 src=r0 offset=0 imm=-4
#line 171 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1810 dst=r1 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=1812 dst=r3 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1813 dst=r0 src=r0 offset=0 imm=16
#line 171 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 171 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 171 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 171 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1814 dst=r7 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1815 dst=r1 src=r7 offset=0 imm=0
#line 171 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=1816 dst=r1 src=r0 offset=0 imm=32
#line 171 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1817 dst=r1 src=r0 offset=0 imm=32
#line 171 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=1818 dst=r1 src=r0 offset=33 imm=0
#line 171 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 171 "sample/map.c"
        goto label_104;
label_101:
    // EBPF_OP_MOV64_IMM pc=1819 dst=r1 src=r0 offset=0 imm=25637
#line 171 "sample/map.c"
    r1 = IMMEDIATE(25637);
    // EBPF_OP_STXH pc=1820 dst=r10 src=r1 offset=-12 imm=0
#line 171 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-12)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=1821 dst=r1 src=r0 offset=0 imm=543450478
#line 171 "sample/map.c"
    r1 = IMMEDIATE(543450478);
    // EBPF_OP_STXW pc=1822 dst=r10 src=r1 offset=-16 imm=0
#line 171 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=1823 dst=r1 src=r0 offset=0 imm=1914725413
#line 171 "sample/map.c"
    r1 = (uint64_t)8247626271654175781;
    // EBPF_OP_STXDW pc=1825 dst=r10 src=r1 offset=-24 imm=0
#line 171 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1826 dst=r1 src=r0 offset=0 imm=1667592312
#line 171 "sample/map.c"
    r1 = (uint64_t)2334102057442963576;
    // EBPF_OP_STXDW pc=1828 dst=r10 src=r1 offset=-32 imm=0
#line 171 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1829 dst=r1 src=r0 offset=0 imm=543649385
#line 171 "sample/map.c"
    r1 = (uint64_t)7286934307705679465;
    // EBPF_OP_STXDW pc=1831 dst=r10 src=r1 offset=-40 imm=0
#line 171 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1832 dst=r1 src=r0 offset=0 imm=1852383341
#line 171 "sample/map.c"
    r1 = (uint64_t)8390880602192683117;
    // EBPF_OP_STXDW pc=1834 dst=r10 src=r1 offset=-48 imm=0
#line 171 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1835 dst=r1 src=r0 offset=0 imm=1752397168
#line 171 "sample/map.c"
    r1 = (uint64_t)7308327755764168048;
    // EBPF_OP_STXDW pc=1837 dst=r10 src=r1 offset=-56 imm=0
#line 171 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1838 dst=r1 src=r0 offset=0 imm=1600548962
#line 171 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1840 dst=r10 src=r1 offset=-64 imm=0
#line 171 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_STXB pc=1841 dst=r10 src=r6 offset=-10 imm=0
#line 171 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-10)) = (uint8_t)r6;
    // EBPF_OP_LDXW pc=1842 dst=r3 src=r10 offset=-4 imm=0
#line 171 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=1843 dst=r5 src=r7 offset=0 imm=0
#line 171 "sample/map.c"
    r5 = r7;
    // EBPF_OP_LSH64_IMM pc=1844 dst=r5 src=r0 offset=0 imm=32
#line 171 "sample/map.c"
    r5 <<= IMMEDIATE(32);
label_102:
    // EBPF_OP_ARSH64_IMM pc=1845 dst=r5 src=r0 offset=0 imm=32
#line 171 "sample/map.c"
    r5 = (int64_t)r5 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=1846 dst=r1 src=r10 offset=0 imm=0
#line 171 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1847 dst=r1 src=r0 offset=0 imm=-64
#line 171 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=1848 dst=r2 src=r0 offset=0 imm=55
#line 171 "sample/map.c"
    r2 = IMMEDIATE(55);
    // EBPF_OP_MOV64_IMM pc=1849 dst=r4 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r4 = IMMEDIATE(0);
label_103:
    // EBPF_OP_CALL pc=1850 dst=r0 src=r0 offset=0 imm=15
#line 171 "sample/map.c"
    r0 = test_maps_helpers[10].address
#line 171 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 171 "sample/map.c"
    if ((test_maps_helpers[10].tail_call) && (r0 == 0))
#line 171 "sample/map.c"
        return 0;
        // EBPF_OP_JA pc=1851 dst=r0 src=r0 offset=-132 imm=0
#line 171 "sample/map.c"
    goto label_95;
label_104:
    // EBPF_OP_MOV64_IMM pc=1852 dst=r1 src=r0 offset=0 imm=1
#line 171 "sample/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=1853 dst=r10 src=r1 offset=-4 imm=0
#line 171 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1854 dst=r2 src=r10 offset=0 imm=0
#line 171 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1855 dst=r2 src=r0 offset=0 imm=-4
#line 171 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1856 dst=r1 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=1858 dst=r3 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1859 dst=r0 src=r0 offset=0 imm=16
#line 171 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 171 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 171 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 171 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1860 dst=r7 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1861 dst=r1 src=r7 offset=0 imm=0
#line 171 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=1862 dst=r1 src=r0 offset=0 imm=32
#line 171 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1863 dst=r1 src=r0 offset=0 imm=32
#line 171 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=1864 dst=r1 src=r0 offset=1 imm=0
#line 171 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 171 "sample/map.c"
        goto label_105;
        // EBPF_OP_JA pc=1865 dst=r0 src=r0 offset=-47 imm=0
#line 171 "sample/map.c"
    goto label_101;
label_105:
    // EBPF_OP_MOV64_IMM pc=1866 dst=r1 src=r0 offset=0 imm=2
#line 171 "sample/map.c"
    r1 = IMMEDIATE(2);
    // EBPF_OP_STXW pc=1867 dst=r10 src=r1 offset=-4 imm=0
#line 171 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1868 dst=r2 src=r10 offset=0 imm=0
#line 171 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1869 dst=r2 src=r0 offset=0 imm=-4
#line 171 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1870 dst=r1 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=1872 dst=r3 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1873 dst=r0 src=r0 offset=0 imm=16
#line 171 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 171 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 171 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 171 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1874 dst=r7 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1875 dst=r1 src=r7 offset=0 imm=0
#line 171 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=1876 dst=r1 src=r0 offset=0 imm=32
#line 171 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1877 dst=r1 src=r0 offset=0 imm=32
#line 171 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1878 dst=r1 src=r0 offset=-60 imm=0
#line 171 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 171 "sample/map.c"
        goto label_101;
        // EBPF_OP_MOV64_IMM pc=1879 dst=r1 src=r0 offset=0 imm=3
#line 171 "sample/map.c"
    r1 = IMMEDIATE(3);
    // EBPF_OP_STXW pc=1880 dst=r10 src=r1 offset=-4 imm=0
#line 171 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1881 dst=r2 src=r10 offset=0 imm=0
#line 171 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1882 dst=r2 src=r0 offset=0 imm=-4
#line 171 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1883 dst=r1 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=1885 dst=r3 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1886 dst=r0 src=r0 offset=0 imm=16
#line 171 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 171 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 171 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 171 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1887 dst=r7 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1888 dst=r1 src=r7 offset=0 imm=0
#line 171 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=1889 dst=r1 src=r0 offset=0 imm=32
#line 171 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1890 dst=r1 src=r0 offset=0 imm=32
#line 171 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1891 dst=r1 src=r0 offset=-73 imm=0
#line 171 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 171 "sample/map.c"
        goto label_101;
        // EBPF_OP_MOV64_IMM pc=1892 dst=r1 src=r0 offset=0 imm=4
#line 171 "sample/map.c"
    r1 = IMMEDIATE(4);
    // EBPF_OP_STXW pc=1893 dst=r10 src=r1 offset=-4 imm=0
#line 171 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1894 dst=r2 src=r10 offset=0 imm=0
#line 171 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1895 dst=r2 src=r0 offset=0 imm=-4
#line 171 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1896 dst=r1 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=1898 dst=r3 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1899 dst=r0 src=r0 offset=0 imm=16
#line 171 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 171 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 171 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 171 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1900 dst=r7 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1901 dst=r1 src=r7 offset=0 imm=0
#line 171 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=1902 dst=r1 src=r0 offset=0 imm=32
#line 171 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1903 dst=r1 src=r0 offset=0 imm=32
#line 171 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1904 dst=r1 src=r0 offset=-86 imm=0
#line 171 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 171 "sample/map.c"
        goto label_101;
        // EBPF_OP_MOV64_IMM pc=1905 dst=r1 src=r0 offset=0 imm=5
#line 171 "sample/map.c"
    r1 = IMMEDIATE(5);
    // EBPF_OP_STXW pc=1906 dst=r10 src=r1 offset=-4 imm=0
#line 171 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1907 dst=r2 src=r10 offset=0 imm=0
#line 171 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1908 dst=r2 src=r0 offset=0 imm=-4
#line 171 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1909 dst=r1 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=1911 dst=r3 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1912 dst=r0 src=r0 offset=0 imm=16
#line 171 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 171 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 171 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 171 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1913 dst=r7 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1914 dst=r1 src=r7 offset=0 imm=0
#line 171 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=1915 dst=r1 src=r0 offset=0 imm=32
#line 171 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1916 dst=r1 src=r0 offset=0 imm=32
#line 171 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1917 dst=r1 src=r0 offset=-99 imm=0
#line 171 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 171 "sample/map.c"
        goto label_101;
        // EBPF_OP_MOV64_IMM pc=1918 dst=r1 src=r0 offset=0 imm=6
#line 171 "sample/map.c"
    r1 = IMMEDIATE(6);
    // EBPF_OP_STXW pc=1919 dst=r10 src=r1 offset=-4 imm=0
#line 171 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1920 dst=r2 src=r10 offset=0 imm=0
#line 171 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1921 dst=r2 src=r0 offset=0 imm=-4
#line 171 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1922 dst=r1 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=1924 dst=r3 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1925 dst=r0 src=r0 offset=0 imm=16
#line 171 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 171 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 171 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 171 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1926 dst=r7 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1927 dst=r1 src=r7 offset=0 imm=0
#line 171 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=1928 dst=r1 src=r0 offset=0 imm=32
#line 171 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1929 dst=r1 src=r0 offset=0 imm=32
#line 171 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1930 dst=r1 src=r0 offset=-112 imm=0
#line 171 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 171 "sample/map.c"
        goto label_101;
        // EBPF_OP_MOV64_IMM pc=1931 dst=r1 src=r0 offset=0 imm=7
#line 171 "sample/map.c"
    r1 = IMMEDIATE(7);
    // EBPF_OP_STXW pc=1932 dst=r10 src=r1 offset=-4 imm=0
#line 171 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1933 dst=r2 src=r10 offset=0 imm=0
#line 171 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1934 dst=r2 src=r0 offset=0 imm=-4
#line 171 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1935 dst=r1 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=1937 dst=r3 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1938 dst=r0 src=r0 offset=0 imm=16
#line 171 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 171 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 171 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 171 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1939 dst=r7 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1940 dst=r1 src=r7 offset=0 imm=0
#line 171 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=1941 dst=r1 src=r0 offset=0 imm=32
#line 171 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1942 dst=r1 src=r0 offset=0 imm=32
#line 171 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1943 dst=r1 src=r0 offset=-125 imm=0
#line 171 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 171 "sample/map.c"
        goto label_101;
        // EBPF_OP_MOV64_IMM pc=1944 dst=r1 src=r0 offset=0 imm=8
#line 171 "sample/map.c"
    r1 = IMMEDIATE(8);
    // EBPF_OP_STXW pc=1945 dst=r10 src=r1 offset=-4 imm=0
#line 171 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1946 dst=r2 src=r10 offset=0 imm=0
#line 171 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1947 dst=r2 src=r0 offset=0 imm=-4
#line 171 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1948 dst=r1 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=1950 dst=r3 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1951 dst=r0 src=r0 offset=0 imm=16
#line 171 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 171 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 171 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 171 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1952 dst=r7 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1953 dst=r1 src=r7 offset=0 imm=0
#line 171 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=1954 dst=r1 src=r0 offset=0 imm=32
#line 171 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1955 dst=r1 src=r0 offset=0 imm=32
#line 171 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1956 dst=r1 src=r0 offset=-138 imm=0
#line 171 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 171 "sample/map.c"
        goto label_101;
        // EBPF_OP_MOV64_IMM pc=1957 dst=r1 src=r0 offset=0 imm=9
#line 171 "sample/map.c"
    r1 = IMMEDIATE(9);
    // EBPF_OP_STXW pc=1958 dst=r10 src=r1 offset=-4 imm=0
#line 171 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1959 dst=r2 src=r10 offset=0 imm=0
#line 171 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1960 dst=r2 src=r0 offset=0 imm=-4
#line 171 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1961 dst=r1 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=1963 dst=r3 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1964 dst=r0 src=r0 offset=0 imm=16
#line 171 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 171 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 171 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 171 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1965 dst=r7 src=r0 offset=0 imm=0
#line 171 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1966 dst=r1 src=r7 offset=0 imm=0
#line 171 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=1967 dst=r1 src=r0 offset=0 imm=32
#line 171 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=1968 dst=r1 src=r0 offset=0 imm=32
#line 171 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=1969 dst=r1 src=r0 offset=-151 imm=0
#line 171 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 171 "sample/map.c"
        goto label_101;
        // EBPF_OP_MOV64_IMM pc=1970 dst=r6 src=r0 offset=0 imm=10
#line 171 "sample/map.c"
    r6 = IMMEDIATE(10);
    // EBPF_OP_STXW pc=1971 dst=r10 src=r6 offset=-4 imm=0
#line 174 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=1972 dst=r2 src=r10 offset=0 imm=0
#line 174 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1973 dst=r2 src=r0 offset=0 imm=-4
#line 174 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_IMM pc=1974 dst=r8 src=r0 offset=0 imm=0
#line 174 "sample/map.c"
    r8 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=1975 dst=r1 src=r0 offset=0 imm=0
#line 174 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=1977 dst=r3 src=r0 offset=0 imm=0
#line 174 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1978 dst=r0 src=r0 offset=0 imm=16
#line 174 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 174 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 174 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 174 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=1979 dst=r7 src=r0 offset=0 imm=0
#line 174 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1980 dst=r5 src=r7 offset=0 imm=0
#line 174 "sample/map.c"
    r5 = r7;
    // EBPF_OP_LSH64_IMM pc=1981 dst=r5 src=r0 offset=0 imm=32
#line 174 "sample/map.c"
    r5 <<= IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=1982 dst=r1 src=r5 offset=0 imm=0
#line 174 "sample/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=1983 dst=r1 src=r0 offset=0 imm=32
#line 174 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_LDDW pc=1984 dst=r2 src=r0 offset=0 imm=-29
#line 174 "sample/map.c"
    r2 = (uint64_t)4294967267;
    // EBPF_OP_JEQ_REG pc=1986 dst=r1 src=r2 offset=30 imm=0
#line 174 "sample/map.c"
    if (r1 == r2)
#line 174 "sample/map.c"
        goto label_106;
        // EBPF_OP_STXB pc=1987 dst=r10 src=r8 offset=-10 imm=0
#line 174 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-10)) = (uint8_t)r8;
    // EBPF_OP_MOV64_IMM pc=1988 dst=r1 src=r0 offset=0 imm=25637
#line 174 "sample/map.c"
    r1 = IMMEDIATE(25637);
    // EBPF_OP_STXH pc=1989 dst=r10 src=r1 offset=-12 imm=0
#line 174 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-12)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=1990 dst=r1 src=r0 offset=0 imm=543450478
#line 174 "sample/map.c"
    r1 = IMMEDIATE(543450478);
    // EBPF_OP_STXW pc=1991 dst=r10 src=r1 offset=-16 imm=0
#line 174 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=1992 dst=r1 src=r0 offset=0 imm=1914725413
#line 174 "sample/map.c"
    r1 = (uint64_t)8247626271654175781;
    // EBPF_OP_STXDW pc=1994 dst=r10 src=r1 offset=-24 imm=0
#line 174 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1995 dst=r1 src=r0 offset=0 imm=1667592312
#line 174 "sample/map.c"
    r1 = (uint64_t)2334102057442963576;
    // EBPF_OP_STXDW pc=1997 dst=r10 src=r1 offset=-32 imm=0
#line 174 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1998 dst=r1 src=r0 offset=0 imm=543649385
#line 174 "sample/map.c"
    r1 = (uint64_t)7286934307705679465;
    // EBPF_OP_STXDW pc=2000 dst=r10 src=r1 offset=-40 imm=0
#line 174 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2001 dst=r1 src=r0 offset=0 imm=1852383341
#line 174 "sample/map.c"
    r1 = (uint64_t)8390880602192683117;
    // EBPF_OP_STXDW pc=2003 dst=r10 src=r1 offset=-48 imm=0
#line 174 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2004 dst=r1 src=r0 offset=0 imm=1752397168
#line 174 "sample/map.c"
    r1 = (uint64_t)7308327755764168048;
    // EBPF_OP_STXDW pc=2006 dst=r10 src=r1 offset=-56 imm=0
#line 174 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2007 dst=r1 src=r0 offset=0 imm=1600548962
#line 174 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2009 dst=r10 src=r1 offset=-64 imm=0
#line 174 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=2010 dst=r3 src=r10 offset=-4 imm=0
#line 174 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_ARSH64_IMM pc=2011 dst=r5 src=r0 offset=0 imm=32
#line 174 "sample/map.c"
    r5 = (int64_t)r5 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=2012 dst=r1 src=r10 offset=0 imm=0
#line 174 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2013 dst=r1 src=r0 offset=0 imm=-64
#line 174 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=2014 dst=r2 src=r0 offset=0 imm=55
#line 174 "sample/map.c"
    r2 = IMMEDIATE(55);
    // EBPF_OP_MOV64_IMM pc=2015 dst=r4 src=r0 offset=0 imm=-29
#line 174 "sample/map.c"
    r4 = IMMEDIATE(-29);
    // EBPF_OP_JA pc=2016 dst=r0 src=r0 offset=-167 imm=0
#line 174 "sample/map.c"
    goto label_103;
label_106:
    // EBPF_OP_STXW pc=2017 dst=r10 src=r6 offset=-4 imm=0
#line 175 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=2018 dst=r2 src=r10 offset=0 imm=0
#line 175 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2019 dst=r2 src=r0 offset=0 imm=-4
#line 175 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2020 dst=r1 src=r0 offset=0 imm=0
#line 175 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_MOV64_IMM pc=2022 dst=r3 src=r0 offset=0 imm=2
#line 175 "sample/map.c"
    r3 = IMMEDIATE(2);
    // EBPF_OP_CALL pc=2023 dst=r0 src=r0 offset=0 imm=16
#line 175 "sample/map.c"
    r0 = test_maps_helpers[9].address
#line 175 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 175 "sample/map.c"
    if ((test_maps_helpers[9].tail_call) && (r0 == 0))
#line 175 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2024 dst=r7 src=r0 offset=0 imm=0
#line 175 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2025 dst=r5 src=r7 offset=0 imm=0
#line 175 "sample/map.c"
    r5 = r7;
    // EBPF_OP_LSH64_IMM pc=2026 dst=r5 src=r0 offset=0 imm=32
#line 175 "sample/map.c"
    r5 <<= IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=2027 dst=r1 src=r5 offset=0 imm=0
#line 175 "sample/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=2028 dst=r1 src=r0 offset=0 imm=32
#line 175 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=2029 dst=r1 src=r0 offset=26 imm=0
#line 175 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 175 "sample/map.c"
        goto label_107;
        // EBPF_OP_MOV64_IMM pc=2030 dst=r1 src=r0 offset=0 imm=25637
#line 175 "sample/map.c"
    r1 = IMMEDIATE(25637);
    // EBPF_OP_STXH pc=2031 dst=r10 src=r1 offset=-12 imm=0
#line 175 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-12)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=2032 dst=r1 src=r0 offset=0 imm=543450478
#line 175 "sample/map.c"
    r1 = IMMEDIATE(543450478);
    // EBPF_OP_STXW pc=2033 dst=r10 src=r1 offset=-16 imm=0
#line 175 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=2034 dst=r1 src=r0 offset=0 imm=1914725413
#line 175 "sample/map.c"
    r1 = (uint64_t)8247626271654175781;
    // EBPF_OP_STXDW pc=2036 dst=r10 src=r1 offset=-24 imm=0
#line 175 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2037 dst=r1 src=r0 offset=0 imm=1667592312
#line 175 "sample/map.c"
    r1 = (uint64_t)2334102057442963576;
    // EBPF_OP_STXDW pc=2039 dst=r10 src=r1 offset=-32 imm=0
#line 175 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2040 dst=r1 src=r0 offset=0 imm=543649385
#line 175 "sample/map.c"
    r1 = (uint64_t)7286934307705679465;
    // EBPF_OP_STXDW pc=2042 dst=r10 src=r1 offset=-40 imm=0
#line 175 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2043 dst=r1 src=r0 offset=0 imm=1852383341
#line 175 "sample/map.c"
    r1 = (uint64_t)8390880602192683117;
    // EBPF_OP_STXDW pc=2045 dst=r10 src=r1 offset=-48 imm=0
#line 175 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2046 dst=r1 src=r0 offset=0 imm=1752397168
#line 175 "sample/map.c"
    r1 = (uint64_t)7308327755764168048;
    // EBPF_OP_STXDW pc=2048 dst=r10 src=r1 offset=-56 imm=0
#line 175 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2049 dst=r1 src=r0 offset=0 imm=1600548962
#line 175 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2051 dst=r10 src=r1 offset=-64 imm=0
#line 175 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_IMM pc=2052 dst=r1 src=r0 offset=0 imm=0
#line 175 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=2053 dst=r10 src=r1 offset=-10 imm=0
#line 175 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-10)) = (uint8_t)r1;
    // EBPF_OP_LDXW pc=2054 dst=r3 src=r10 offset=-4 imm=0
#line 175 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JA pc=2055 dst=r0 src=r0 offset=-211 imm=0
#line 175 "sample/map.c"
    goto label_102;
label_107:
    // EBPF_OP_MOV64_IMM pc=2056 dst=r1 src=r0 offset=0 imm=0
#line 175 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2057 dst=r10 src=r1 offset=-4 imm=0
#line 177 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=2058 dst=r2 src=r10 offset=0 imm=0
#line 177 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2059 dst=r2 src=r0 offset=0 imm=-4
#line 177 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2060 dst=r1 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=2062 dst=r0 src=r0 offset=0 imm=18
#line 177 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 177 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 177 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 177 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2063 dst=r7 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2064 dst=r4 src=r7 offset=0 imm=0
#line 177 "sample/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=2065 dst=r4 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r4 <<= IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=2066 dst=r1 src=r4 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=2067 dst=r1 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=2068 dst=r1 src=r0 offset=27 imm=0
#line 177 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 177 "sample/map.c"
        goto label_109;
        // EBPF_OP_MOV64_IMM pc=2069 dst=r1 src=r0 offset=0 imm=100
#line 177 "sample/map.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXH pc=2070 dst=r10 src=r1 offset=-16 imm=0
#line 177 "sample/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=2071 dst=r1 src=r0 offset=0 imm=1852994932
#line 177 "sample/map.c"
    r1 = (uint64_t)2675248565465544052;
    // EBPF_OP_STXDW pc=2073 dst=r10 src=r1 offset=-24 imm=0
#line 177 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2074 dst=r1 src=r0 offset=0 imm=622883948
#line 177 "sample/map.c"
    r1 = (uint64_t)7309940759667438700;
    // EBPF_OP_STXDW pc=2076 dst=r10 src=r1 offset=-32 imm=0
#line 177 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2077 dst=r1 src=r0 offset=0 imm=543649385
#line 177 "sample/map.c"
    r1 = (uint64_t)8463219665603620457;
    // EBPF_OP_STXDW pc=2079 dst=r10 src=r1 offset=-40 imm=0
#line 177 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2080 dst=r1 src=r0 offset=0 imm=2019893357
#line 177 "sample/map.c"
    r1 = (uint64_t)8386658464824631405;
    // EBPF_OP_STXDW pc=2082 dst=r10 src=r1 offset=-48 imm=0
#line 177 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2083 dst=r1 src=r0 offset=0 imm=1801807216
#line 177 "sample/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=2085 dst=r10 src=r1 offset=-56 imm=0
#line 177 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2086 dst=r1 src=r0 offset=0 imm=1600548962
#line 177 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2088 dst=r10 src=r1 offset=-64 imm=0
#line 177 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_ARSH64_IMM pc=2089 dst=r4 src=r0 offset=0 imm=32
#line 177 "sample/map.c"
    r4 = (int64_t)r4 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=2090 dst=r1 src=r10 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2091 dst=r1 src=r0 offset=0 imm=-64
#line 177 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=2092 dst=r2 src=r0 offset=0 imm=50
#line 177 "sample/map.c"
    r2 = IMMEDIATE(50);
label_108:
    // EBPF_OP_MOV64_IMM pc=2093 dst=r3 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=2094 dst=r0 src=r0 offset=0 imm=14
#line 177 "sample/map.c"
    r0 = test_maps_helpers[7].address
#line 177 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 177 "sample/map.c"
    if ((test_maps_helpers[7].tail_call) && (r0 == 0))
#line 177 "sample/map.c"
        return 0;
        // EBPF_OP_JA pc=2095 dst=r0 src=r0 offset=-376 imm=0
#line 177 "sample/map.c"
    goto label_95;
label_109:
    // EBPF_OP_LDXW pc=2096 dst=r3 src=r10 offset=-4 imm=0
#line 177 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=2097 dst=r3 src=r0 offset=22 imm=10
#line 177 "sample/map.c"
    if (r3 == IMMEDIATE(10))
#line 177 "sample/map.c"
        goto label_110;
        // EBPF_OP_MOV64_IMM pc=2098 dst=r1 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=2099 dst=r10 src=r1 offset=-24 imm=0
#line 177 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint8_t)r1;
    // EBPF_OP_LDDW pc=2100 dst=r1 src=r0 offset=0 imm=1852404835
#line 177 "sample/map.c"
    r1 = (uint64_t)7216209606537213027;
    // EBPF_OP_STXDW pc=2102 dst=r10 src=r1 offset=-32 imm=0
#line 177 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2103 dst=r1 src=r0 offset=0 imm=543434016
#line 177 "sample/map.c"
    r1 = (uint64_t)7309474570952779040;
    // EBPF_OP_STXDW pc=2105 dst=r10 src=r1 offset=-40 imm=0
#line 177 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2106 dst=r1 src=r0 offset=0 imm=1701978221
#line 177 "sample/map.c"
    r1 = (uint64_t)7958552634295722093;
    // EBPF_OP_STXDW pc=2108 dst=r10 src=r1 offset=-48 imm=0
#line 177 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2109 dst=r1 src=r0 offset=0 imm=1801807216
#line 177 "sample/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=2111 dst=r10 src=r1 offset=-56 imm=0
#line 177 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2112 dst=r1 src=r0 offset=0 imm=1600548962
#line 177 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2114 dst=r10 src=r1 offset=-64 imm=0
#line 177 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=2115 dst=r1 src=r10 offset=0 imm=0
#line 177 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2116 dst=r1 src=r0 offset=0 imm=-64
#line 177 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=2117 dst=r2 src=r0 offset=0 imm=41
#line 177 "sample/map.c"
    r2 = IMMEDIATE(41);
    // EBPF_OP_MOV64_IMM pc=2118 dst=r4 src=r0 offset=0 imm=10
#line 177 "sample/map.c"
    r4 = IMMEDIATE(10);
    // EBPF_OP_JA pc=2119 dst=r0 src=r0 offset=-403 imm=0
#line 177 "sample/map.c"
    goto label_94;
label_110:
    // EBPF_OP_MOV64_IMM pc=2120 dst=r6 src=r0 offset=0 imm=0
#line 177 "sample/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2121 dst=r10 src=r6 offset=-4 imm=0
#line 180 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=2122 dst=r2 src=r10 offset=0 imm=0
#line 180 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2123 dst=r2 src=r0 offset=0 imm=-4
#line 180 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2124 dst=r1 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=2126 dst=r0 src=r0 offset=0 imm=17
#line 180 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 180 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 180 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 180 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2127 dst=r7 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2128 dst=r1 src=r7 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=2129 dst=r1 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=2130 dst=r1 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=2131 dst=r1 src=r0 offset=26 imm=0
#line 180 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 180 "sample/map.c"
        goto label_112;
label_111:
    // EBPF_OP_LDDW pc=2132 dst=r1 src=r0 offset=0 imm=1701737077
#line 180 "sample/map.c"
    r1 = (uint64_t)7216209593501643381;
    // EBPF_OP_STXDW pc=2134 dst=r10 src=r1 offset=-24 imm=0
#line 180 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2135 dst=r1 src=r0 offset=0 imm=1680154740
#line 180 "sample/map.c"
    r1 = (uint64_t)8387235364492091508;
    // EBPF_OP_STXDW pc=2137 dst=r10 src=r1 offset=-32 imm=0
#line 180 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2138 dst=r1 src=r0 offset=0 imm=1914726254
#line 180 "sample/map.c"
    r1 = (uint64_t)7815279607914981230;
    // EBPF_OP_STXDW pc=2140 dst=r10 src=r1 offset=-40 imm=0
#line 180 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2141 dst=r1 src=r0 offset=0 imm=1886938400
#line 180 "sample/map.c"
    r1 = (uint64_t)7598807758610654496;
    // EBPF_OP_STXDW pc=2143 dst=r10 src=r1 offset=-48 imm=0
#line 180 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2144 dst=r1 src=r0 offset=0 imm=1601204080
#line 180 "sample/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=2146 dst=r10 src=r1 offset=-56 imm=0
#line 180 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2147 dst=r1 src=r0 offset=0 imm=1600548962
#line 180 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2149 dst=r10 src=r1 offset=-64 imm=0
#line 180 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_STXB pc=2150 dst=r10 src=r6 offset=-16 imm=0
#line 180 "sample/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint8_t)r6;
    // EBPF_OP_MOV64_REG pc=2151 dst=r4 src=r7 offset=0 imm=0
#line 180 "sample/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=2152 dst=r4 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r4 <<= IMMEDIATE(32);
    // EBPF_OP_ARSH64_IMM pc=2153 dst=r4 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r4 = (int64_t)r4 >> (uint32_t)IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=2154 dst=r1 src=r10 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2155 dst=r1 src=r0 offset=0 imm=-64
#line 180 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=2156 dst=r2 src=r0 offset=0 imm=49
#line 180 "sample/map.c"
    r2 = IMMEDIATE(49);
    // EBPF_OP_JA pc=2157 dst=r0 src=r0 offset=-65 imm=0
#line 180 "sample/map.c"
    goto label_108;
label_112:
    // EBPF_OP_MOV64_IMM pc=2158 dst=r4 src=r0 offset=0 imm=10
#line 180 "sample/map.c"
    r4 = IMMEDIATE(10);
    // EBPF_OP_LDXW pc=2159 dst=r3 src=r10 offset=-4 imm=0
#line 180 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=2160 dst=r3 src=r0 offset=19 imm=10
#line 180 "sample/map.c"
    if (r3 == IMMEDIATE(10))
#line 180 "sample/map.c"
        goto label_114;
label_113:
    // EBPF_OP_LDDW pc=2161 dst=r1 src=r0 offset=0 imm=1735289204
#line 180 "sample/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=2163 dst=r10 src=r1 offset=-32 imm=0
#line 180 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2164 dst=r1 src=r0 offset=0 imm=1696621605
#line 180 "sample/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=2166 dst=r10 src=r1 offset=-40 imm=0
#line 180 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2167 dst=r1 src=r0 offset=0 imm=1952805408
#line 180 "sample/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=2169 dst=r10 src=r1 offset=-48 imm=0
#line 180 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2170 dst=r1 src=r0 offset=0 imm=1601204080
#line 180 "sample/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=2172 dst=r10 src=r1 offset=-56 imm=0
#line 180 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2173 dst=r1 src=r0 offset=0 imm=1600548962
#line 180 "sample/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2175 dst=r10 src=r1 offset=-64 imm=0
#line 180 "sample/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=2176 dst=r1 src=r10 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2177 dst=r1 src=r0 offset=0 imm=-64
#line 180 "sample/map.c"
    r1 += IMMEDIATE(-64);
    // EBPF_OP_MOV64_IMM pc=2178 dst=r2 src=r0 offset=0 imm=40
#line 180 "sample/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_JA pc=2179 dst=r0 src=r0 offset=-463 imm=0
#line 180 "sample/map.c"
    goto label_94;
label_114:
    // EBPF_OP_MOV64_IMM pc=2180 dst=r1 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2181 dst=r10 src=r1 offset=-4 imm=0
#line 180 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=2182 dst=r2 src=r10 offset=0 imm=0
#line 180 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2183 dst=r2 src=r0 offset=0 imm=-4
#line 180 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2184 dst=r1 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=2186 dst=r0 src=r0 offset=0 imm=17
#line 180 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 180 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 180 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 180 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2187 dst=r7 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2188 dst=r1 src=r7 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=2189 dst=r1 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=2190 dst=r1 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JEQ_IMM pc=2191 dst=r1 src=r0 offset=1 imm=0
#line 180 "sample/map.c"
    if (r1 == IMMEDIATE(0))
#line 180 "sample/map.c"
        goto label_115;
        // EBPF_OP_JA pc=2192 dst=r0 src=r0 offset=-61 imm=0
#line 180 "sample/map.c"
    goto label_111;
label_115:
    // EBPF_OP_MOV64_IMM pc=2193 dst=r4 src=r0 offset=0 imm=9
#line 180 "sample/map.c"
    r4 = IMMEDIATE(9);
    // EBPF_OP_LDXW pc=2194 dst=r3 src=r10 offset=-4 imm=0
#line 180 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=2195 dst=r3 src=r0 offset=-35 imm=9
#line 180 "sample/map.c"
    if (r3 != IMMEDIATE(9))
#line 180 "sample/map.c"
        goto label_113;
        // EBPF_OP_MOV64_IMM pc=2196 dst=r1 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2197 dst=r10 src=r1 offset=-4 imm=0
#line 180 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=2198 dst=r2 src=r10 offset=0 imm=0
#line 180 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2199 dst=r2 src=r0 offset=0 imm=-4
#line 180 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2200 dst=r1 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=2202 dst=r0 src=r0 offset=0 imm=17
#line 180 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 180 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 180 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 180 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2203 dst=r7 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2204 dst=r1 src=r7 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=2205 dst=r1 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=2206 dst=r1 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=2207 dst=r1 src=r0 offset=-76 imm=0
#line 180 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 180 "sample/map.c"
        goto label_111;
        // EBPF_OP_MOV64_IMM pc=2208 dst=r4 src=r0 offset=0 imm=8
#line 180 "sample/map.c"
    r4 = IMMEDIATE(8);
    // EBPF_OP_LDXW pc=2209 dst=r3 src=r10 offset=-4 imm=0
#line 180 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=2210 dst=r3 src=r0 offset=-50 imm=8
#line 180 "sample/map.c"
    if (r3 != IMMEDIATE(8))
#line 180 "sample/map.c"
        goto label_113;
        // EBPF_OP_MOV64_IMM pc=2211 dst=r1 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2212 dst=r10 src=r1 offset=-4 imm=0
#line 180 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=2213 dst=r2 src=r10 offset=0 imm=0
#line 180 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2214 dst=r2 src=r0 offset=0 imm=-4
#line 180 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2215 dst=r1 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=2217 dst=r0 src=r0 offset=0 imm=17
#line 180 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 180 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 180 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 180 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2218 dst=r7 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2219 dst=r1 src=r7 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=2220 dst=r1 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=2221 dst=r1 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=2222 dst=r1 src=r0 offset=-91 imm=0
#line 180 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 180 "sample/map.c"
        goto label_111;
        // EBPF_OP_MOV64_IMM pc=2223 dst=r4 src=r0 offset=0 imm=7
#line 180 "sample/map.c"
    r4 = IMMEDIATE(7);
    // EBPF_OP_LDXW pc=2224 dst=r3 src=r10 offset=-4 imm=0
#line 180 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=2225 dst=r3 src=r0 offset=-65 imm=7
#line 180 "sample/map.c"
    if (r3 != IMMEDIATE(7))
#line 180 "sample/map.c"
        goto label_113;
        // EBPF_OP_MOV64_IMM pc=2226 dst=r1 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2227 dst=r10 src=r1 offset=-4 imm=0
#line 180 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=2228 dst=r2 src=r10 offset=0 imm=0
#line 180 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2229 dst=r2 src=r0 offset=0 imm=-4
#line 180 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2230 dst=r1 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=2232 dst=r0 src=r0 offset=0 imm=17
#line 180 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 180 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 180 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 180 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2233 dst=r7 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2234 dst=r1 src=r7 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=2235 dst=r1 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=2236 dst=r1 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=2237 dst=r1 src=r0 offset=-106 imm=0
#line 180 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 180 "sample/map.c"
        goto label_111;
        // EBPF_OP_MOV64_IMM pc=2238 dst=r4 src=r0 offset=0 imm=6
#line 180 "sample/map.c"
    r4 = IMMEDIATE(6);
    // EBPF_OP_LDXW pc=2239 dst=r3 src=r10 offset=-4 imm=0
#line 180 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=2240 dst=r3 src=r0 offset=-80 imm=6
#line 180 "sample/map.c"
    if (r3 != IMMEDIATE(6))
#line 180 "sample/map.c"
        goto label_113;
        // EBPF_OP_MOV64_IMM pc=2241 dst=r1 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2242 dst=r10 src=r1 offset=-4 imm=0
#line 180 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=2243 dst=r2 src=r10 offset=0 imm=0
#line 180 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2244 dst=r2 src=r0 offset=0 imm=-4
#line 180 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2245 dst=r1 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=2247 dst=r0 src=r0 offset=0 imm=17
#line 180 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 180 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 180 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 180 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2248 dst=r7 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2249 dst=r1 src=r7 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=2250 dst=r1 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=2251 dst=r1 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=2252 dst=r1 src=r0 offset=-121 imm=0
#line 180 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 180 "sample/map.c"
        goto label_111;
        // EBPF_OP_MOV64_IMM pc=2253 dst=r4 src=r0 offset=0 imm=5
#line 180 "sample/map.c"
    r4 = IMMEDIATE(5);
    // EBPF_OP_LDXW pc=2254 dst=r3 src=r10 offset=-4 imm=0
#line 180 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=2255 dst=r3 src=r0 offset=-95 imm=5
#line 180 "sample/map.c"
    if (r3 != IMMEDIATE(5))
#line 180 "sample/map.c"
        goto label_113;
        // EBPF_OP_MOV64_IMM pc=2256 dst=r1 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2257 dst=r10 src=r1 offset=-4 imm=0
#line 180 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=2258 dst=r2 src=r10 offset=0 imm=0
#line 180 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2259 dst=r2 src=r0 offset=0 imm=-4
#line 180 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2260 dst=r1 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=2262 dst=r0 src=r0 offset=0 imm=17
#line 180 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 180 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 180 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 180 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2263 dst=r7 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2264 dst=r1 src=r7 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=2265 dst=r1 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=2266 dst=r1 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=2267 dst=r1 src=r0 offset=-136 imm=0
#line 180 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 180 "sample/map.c"
        goto label_111;
        // EBPF_OP_MOV64_IMM pc=2268 dst=r4 src=r0 offset=0 imm=4
#line 180 "sample/map.c"
    r4 = IMMEDIATE(4);
    // EBPF_OP_LDXW pc=2269 dst=r3 src=r10 offset=-4 imm=0
#line 180 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=2270 dst=r3 src=r0 offset=-110 imm=4
#line 180 "sample/map.c"
    if (r3 != IMMEDIATE(4))
#line 180 "sample/map.c"
        goto label_113;
        // EBPF_OP_MOV64_IMM pc=2271 dst=r1 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2272 dst=r10 src=r1 offset=-4 imm=0
#line 180 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=2273 dst=r2 src=r10 offset=0 imm=0
#line 180 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2274 dst=r2 src=r0 offset=0 imm=-4
#line 180 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2275 dst=r1 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=2277 dst=r0 src=r0 offset=0 imm=17
#line 180 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 180 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 180 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 180 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2278 dst=r7 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2279 dst=r1 src=r7 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=2280 dst=r1 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=2281 dst=r1 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=2282 dst=r1 src=r0 offset=-151 imm=0
#line 180 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 180 "sample/map.c"
        goto label_111;
        // EBPF_OP_MOV64_IMM pc=2283 dst=r4 src=r0 offset=0 imm=3
#line 180 "sample/map.c"
    r4 = IMMEDIATE(3);
    // EBPF_OP_LDXW pc=2284 dst=r3 src=r10 offset=-4 imm=0
#line 180 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=2285 dst=r3 src=r0 offset=-125 imm=3
#line 180 "sample/map.c"
    if (r3 != IMMEDIATE(3))
#line 180 "sample/map.c"
        goto label_113;
        // EBPF_OP_MOV64_IMM pc=2286 dst=r1 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2287 dst=r10 src=r1 offset=-4 imm=0
#line 180 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=2288 dst=r2 src=r10 offset=0 imm=0
#line 180 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2289 dst=r2 src=r0 offset=0 imm=-4
#line 180 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2290 dst=r1 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=2292 dst=r0 src=r0 offset=0 imm=17
#line 180 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 180 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 180 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 180 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2293 dst=r7 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2294 dst=r1 src=r7 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=2295 dst=r1 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=2296 dst=r1 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=2297 dst=r1 src=r0 offset=-166 imm=0
#line 180 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 180 "sample/map.c"
        goto label_111;
        // EBPF_OP_MOV64_IMM pc=2298 dst=r4 src=r0 offset=0 imm=2
#line 180 "sample/map.c"
    r4 = IMMEDIATE(2);
    // EBPF_OP_LDXW pc=2299 dst=r3 src=r10 offset=-4 imm=0
#line 180 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=2300 dst=r3 src=r0 offset=-140 imm=2
#line 180 "sample/map.c"
    if (r3 != IMMEDIATE(2))
#line 180 "sample/map.c"
        goto label_113;
        // EBPF_OP_MOV64_IMM pc=2301 dst=r1 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2302 dst=r10 src=r1 offset=-4 imm=0
#line 180 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=2303 dst=r2 src=r10 offset=0 imm=0
#line 180 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2304 dst=r2 src=r0 offset=0 imm=-4
#line 180 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2305 dst=r1 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=2307 dst=r0 src=r0 offset=0 imm=17
#line 180 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 180 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 180 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 180 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2308 dst=r7 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2309 dst=r1 src=r7 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = r7;
    // EBPF_OP_LSH64_IMM pc=2310 dst=r1 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r1 <<= IMMEDIATE(32);
    // EBPF_OP_RSH64_IMM pc=2311 dst=r1 src=r0 offset=0 imm=32
#line 180 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_JNE_IMM pc=2312 dst=r1 src=r0 offset=-181 imm=0
#line 180 "sample/map.c"
    if (r1 != IMMEDIATE(0))
#line 180 "sample/map.c"
        goto label_111;
        // EBPF_OP_MOV64_IMM pc=2313 dst=r4 src=r0 offset=0 imm=1
#line 180 "sample/map.c"
    r4 = IMMEDIATE(1);
    // EBPF_OP_LDXW pc=2314 dst=r3 src=r10 offset=-4 imm=0
#line 180 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JNE_IMM pc=2315 dst=r3 src=r0 offset=-155 imm=1
#line 180 "sample/map.c"
    if (r3 != IMMEDIATE(1))
#line 180 "sample/map.c"
        goto label_113;
        // EBPF_OP_MOV64_IMM pc=2316 dst=r1 src=r0 offset=0 imm=0
#line 180 "sample/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2317 dst=r10 src=r1 offset=-4 imm=0
#line 183 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=2318 dst=r2 src=r10 offset=0 imm=0
#line 183 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2319 dst=r2 src=r0 offset=0 imm=-4
#line 183 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2320 dst=r1 src=r0 offset=0 imm=0
#line 183 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=2322 dst=r0 src=r0 offset=0 imm=18
#line 183 "sample/map.c"
    r0 = test_maps_helpers[6].address
#line 183 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 183 "sample/map.c"
    if ((test_maps_helpers[6].tail_call) && (r0 == 0))
#line 183 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2323 dst=r7 src=r0 offset=0 imm=0
#line 183 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2324 dst=r4 src=r7 offset=0 imm=0
#line 183 "sample/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=2325 dst=r4 src=r0 offset=0 imm=32
#line 183 "sample/map.c"
    r4 <<= IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=2326 dst=r1 src=r4 offset=0 imm=0
#line 183 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=2327 dst=r1 src=r0 offset=0 imm=32
#line 183 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_LDDW pc=2328 dst=r2 src=r0 offset=0 imm=-7
#line 183 "sample/map.c"
    r2 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=2330 dst=r1 src=r2 offset=1 imm=0
#line 183 "sample/map.c"
    if (r1 == r2)
#line 183 "sample/map.c"
        goto label_116;
        // EBPF_OP_JA pc=2331 dst=r0 src=r0 offset=-665 imm=0
#line 183 "sample/map.c"
    goto label_89;
label_116:
    // EBPF_OP_LDXW pc=2332 dst=r3 src=r10 offset=-4 imm=0
#line 183 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=2333 dst=r3 src=r0 offset=1 imm=0
#line 183 "sample/map.c"
    if (r3 == IMMEDIATE(0))
#line 183 "sample/map.c"
        goto label_117;
        // EBPF_OP_JA pc=2334 dst=r0 src=r0 offset=-639 imm=0
#line 183 "sample/map.c"
    goto label_92;
label_117:
    // EBPF_OP_MOV64_IMM pc=2335 dst=r6 src=r0 offset=0 imm=0
#line 183 "sample/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2336 dst=r10 src=r6 offset=-4 imm=0
#line 184 "sample/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=2337 dst=r2 src=r10 offset=0 imm=0
#line 184 "sample/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2338 dst=r2 src=r0 offset=0 imm=-4
#line 184 "sample/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2339 dst=r1 src=r0 offset=0 imm=0
#line 184 "sample/map.c"
    r1 = POINTER(_maps[7].address);
    // EBPF_OP_CALL pc=2341 dst=r0 src=r0 offset=0 imm=17
#line 184 "sample/map.c"
    r0 = test_maps_helpers[8].address
#line 184 "sample/map.c"
         (r1, r2, r3, r4, r5);
#line 184 "sample/map.c"
    if ((test_maps_helpers[8].tail_call) && (r0 == 0))
#line 184 "sample/map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=2342 dst=r7 src=r0 offset=0 imm=0
#line 184 "sample/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2343 dst=r4 src=r7 offset=0 imm=0
#line 184 "sample/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=2344 dst=r4 src=r0 offset=0 imm=32
#line 184 "sample/map.c"
    r4 <<= IMMEDIATE(32);
    // EBPF_OP_MOV64_REG pc=2345 dst=r1 src=r4 offset=0 imm=0
#line 184 "sample/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=2346 dst=r1 src=r0 offset=0 imm=32
#line 184 "sample/map.c"
    r1 >>= IMMEDIATE(32);
    // EBPF_OP_LDDW pc=2347 dst=r2 src=r0 offset=0 imm=-7
#line 184 "sample/map.c"
    r2 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=2349 dst=r1 src=r2 offset=1 imm=0
#line 184 "sample/map.c"
    if (r1 == r2)
#line 184 "sample/map.c"
        goto label_118;
        // EBPF_OP_JA pc=2350 dst=r0 src=r0 offset=-590 imm=0
#line 184 "sample/map.c"
    goto label_97;
label_118:
    // EBPF_OP_LDXW pc=2351 dst=r3 src=r10 offset=-4 imm=0
#line 184 "sample/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=2352 dst=r3 src=r0 offset=1 imm=0
#line 184 "sample/map.c"
    if (r3 == IMMEDIATE(0))
#line 184 "sample/map.c"
        goto label_119;
        // EBPF_OP_JA pc=2353 dst=r0 src=r0 offset=-567 imm=0
#line 184 "sample/map.c"
    goto label_99;
label_119:
    // EBPF_OP_MOV64_IMM pc=2354 dst=r6 src=r0 offset=0 imm=0
#line 184 "sample/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_JA pc=2355 dst=r0 src=r0 offset=-2254 imm=0
#line 184 "sample/map.c"
    goto label_8;
#line 184 "sample/map.c"
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
        11,
        2356,
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

metadata_table_t map_metadata_table = {_get_programs, _get_maps, _get_hash};
