// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from inner_map.o

#define NO_CRT
#include "bpf2c.h"

#include <guiddef.h>
#include <wdm.h>
#include <wsk.h>

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
RTL_QUERY_REGISTRY_ROUTINE static _bpf2c_query_registry_routine;

#define metadata_table inner_map##_metadata_table

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
         BPF_MAP_TYPE_HASH_OF_MAPS, // Type of map.
         4,                         // Size in bytes of a map key.
         4,                         // Size in bytes of a map value.
         1,                         // Maximum number of entries allowed in the map.
         0,                         // Inner map index.
         LIBBPF_PIN_NONE,           // Pinning type for the map.
         15,                        // Identifier for a map template.
         11,                        // The id of the inner map template.
     },
     "outer_map"},
    {NULL,
     {
         BPF_MAP_TYPE_HASH_OF_MAPS, // Type of map.
         2,                         // Size in bytes of a map key.
         4,                         // Size in bytes of a map value.
         1,                         // Maximum number of entries allowed in the map.
         0,                         // Inner map index.
         LIBBPF_PIN_NONE,           // Pinning type for the map.
         25,                        // Identifier for a map template.
         21,                        // The id of the inner map template.
     },
     "outer_map2"},
    {NULL,
     {
         BPF_MAP_TYPE_ARRAY, // Type of map.
         4,                  // Size in bytes of a map key.
         4,                  // Size in bytes of a map value.
         1024,               // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         LIBBPF_PIN_NONE,    // Pinning type for the map.
         21,                 // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "inner_map"},
    {NULL,
     {
         BPF_MAP_TYPE_ARRAY, // Type of map.
         4,                  // Size in bytes of a map key.
         4,                  // Size in bytes of a map value.
         1,                  // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         LIBBPF_PIN_NONE,    // Pinning type for the map.
         11,                 // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "__anonymous_1"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 4;
}

static helper_function_entry_t lookup_update_helpers[] = {
    {NULL, 1, "helper_id_1"},
};

static GUID lookup_update_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID lookup_update_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t lookup_update_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sample~1")
static uint64_t
lookup_update(void* context)
#line 52 "sample/undocked/inner_map.c"
{
#line 52 "sample/undocked/inner_map.c"
    // Prologue
#line 52 "sample/undocked/inner_map.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 52 "sample/undocked/inner_map.c"
    register uint64_t r0 = 0;
#line 52 "sample/undocked/inner_map.c"
    register uint64_t r1 = 0;
#line 52 "sample/undocked/inner_map.c"
    register uint64_t r2 = 0;
#line 52 "sample/undocked/inner_map.c"
    register uint64_t r3 = 0;
#line 52 "sample/undocked/inner_map.c"
    register uint64_t r4 = 0;
#line 52 "sample/undocked/inner_map.c"
    register uint64_t r5 = 0;
#line 52 "sample/undocked/inner_map.c"
    register uint64_t r6 = 0;
#line 52 "sample/undocked/inner_map.c"
    register uint64_t r7 = 0;
#line 52 "sample/undocked/inner_map.c"
    register uint64_t r10 = 0;

#line 52 "sample/undocked/inner_map.c"
    r1 = (uintptr_t)context;
#line 52 "sample/undocked/inner_map.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r7 src=r0 offset=0 imm=0
#line 52 "sample/undocked/inner_map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1 dst=r10 src=r7 offset=-4 imm=0
#line 54 "sample/undocked/inner_map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_STXH pc=2 dst=r10 src=r7 offset=-6 imm=0
#line 55 "sample/undocked/inner_map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-6)) = (uint16_t)r7;
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 55 "sample/undocked/inner_map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-4
#line 55 "sample/undocked/inner_map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 60 "sample/undocked/inner_map.c"
    r1 = POINTER(_maps[0].address);
    // EBPF_OP_CALL pc=7 dst=r0 src=r0 offset=0 imm=1
#line 60 "sample/undocked/inner_map.c"
    r0 = lookup_update_helpers[0].address
#line 60 "sample/undocked/inner_map.c"
         (r1, r2, r3, r4, r5);
#line 60 "sample/undocked/inner_map.c"
    if ((lookup_update_helpers[0].tail_call) && (r0 == 0))
#line 60 "sample/undocked/inner_map.c"
        return 0;
        // EBPF_OP_MOV64_REG pc=8 dst=r6 src=r0 offset=0 imm=0
#line 60 "sample/undocked/inner_map.c"
    r6 = r0;
    // EBPF_OP_JEQ_IMM pc=9 dst=r6 src=r0 offset=11 imm=0
#line 61 "sample/undocked/inner_map.c"
    if (r6 == IMMEDIATE(0))
#line 61 "sample/undocked/inner_map.c"
        goto label_3;
        // EBPF_OP_STXW pc=10 dst=r10 src=r7 offset=-12 imm=0
#line 62 "sample/undocked/inner_map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-12)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=11 dst=r2 src=r10 offset=0 imm=0
#line 62 "sample/undocked/inner_map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=12 dst=r2 src=r0 offset=0 imm=-12
#line 62 "sample/undocked/inner_map.c"
    r2 += IMMEDIATE(-12);
    // EBPF_OP_MOV64_REG pc=13 dst=r1 src=r6 offset=0 imm=0
#line 63 "sample/undocked/inner_map.c"
    r1 = r6;
    // EBPF_OP_CALL pc=14 dst=r0 src=r0 offset=0 imm=1
#line 63 "sample/undocked/inner_map.c"
    r0 = lookup_update_helpers[0].address
#line 63 "sample/undocked/inner_map.c"
         (r1, r2, r3, r4, r5);
#line 63 "sample/undocked/inner_map.c"
    if ((lookup_update_helpers[0].tail_call) && (r0 == 0))
#line 63 "sample/undocked/inner_map.c"
        return 0;
        // EBPF_OP_JEQ_IMM pc=15 dst=r0 src=r0 offset=5 imm=0
#line 64 "sample/undocked/inner_map.c"
    if (r0 == IMMEDIATE(0))
#line 64 "sample/undocked/inner_map.c"
        goto label_3;
label_1:
    // EBPF_OP_MOV64_IMM pc=16 dst=r1 src=r0 offset=0 imm=1
#line 64 "sample/undocked/inner_map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=17 dst=r0 src=r1 offset=0 imm=0
#line 64 "sample/undocked/inner_map.c"
    *(uint32_t*)(uintptr_t)(r0 + OFFSET(0)) = (uint32_t)r1;
    // EBPF_OP_MOV64_IMM pc=18 dst=r7 src=r0 offset=0 imm=0
#line 64 "sample/undocked/inner_map.c"
    r7 = IMMEDIATE(0);
label_2:
    // EBPF_OP_MOV64_REG pc=19 dst=r0 src=r7 offset=0 imm=0
#line 84 "sample/undocked/inner_map.c"
    r0 = r7;
    // EBPF_OP_EXIT pc=20 dst=r0 src=r0 offset=0 imm=0
#line 84 "sample/undocked/inner_map.c"
    return r0;
label_3:
    // EBPF_OP_MOV64_REG pc=21 dst=r2 src=r10 offset=0 imm=0
#line 84 "sample/undocked/inner_map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=22 dst=r2 src=r0 offset=0 imm=-6
#line 84 "sample/undocked/inner_map.c"
    r2 += IMMEDIATE(-6);
    // EBPF_OP_LDDW pc=23 dst=r1 src=r0 offset=0 imm=0
#line 72 "sample/undocked/inner_map.c"
    r1 = POINTER(_maps[1].address);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=1
#line 72 "sample/undocked/inner_map.c"
    r0 = lookup_update_helpers[0].address
#line 72 "sample/undocked/inner_map.c"
         (r1, r2, r3, r4, r5);
#line 72 "sample/undocked/inner_map.c"
    if ((lookup_update_helpers[0].tail_call) && (r0 == 0))
#line 72 "sample/undocked/inner_map.c"
        return 0;
        // EBPF_OP_MOV64_IMM pc=26 dst=r7 src=r0 offset=0 imm=1
#line 72 "sample/undocked/inner_map.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=27 dst=r0 src=r0 offset=-9 imm=0
#line 73 "sample/undocked/inner_map.c"
    if (r0 == IMMEDIATE(0))
#line 73 "sample/undocked/inner_map.c"
        goto label_2;
        // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=0
#line 73 "sample/undocked/inner_map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=29 dst=r10 src=r1 offset=-16 imm=0
#line 74 "sample/undocked/inner_map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=30 dst=r2 src=r10 offset=0 imm=0
#line 74 "sample/undocked/inner_map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=31 dst=r2 src=r0 offset=0 imm=-16
#line 74 "sample/undocked/inner_map.c"
    r2 += IMMEDIATE(-16);
    // EBPF_OP_MOV64_REG pc=32 dst=r1 src=r6 offset=0 imm=0
#line 75 "sample/undocked/inner_map.c"
    r1 = r6;
    // EBPF_OP_CALL pc=33 dst=r0 src=r0 offset=0 imm=1
#line 75 "sample/undocked/inner_map.c"
    r0 = lookup_update_helpers[0].address
#line 75 "sample/undocked/inner_map.c"
         (r1, r2, r3, r4, r5);
#line 75 "sample/undocked/inner_map.c"
    if ((lookup_update_helpers[0].tail_call) && (r0 == 0))
#line 75 "sample/undocked/inner_map.c"
        return 0;
        // EBPF_OP_JEQ_IMM pc=34 dst=r0 src=r0 offset=-16 imm=0
#line 76 "sample/undocked/inner_map.c"
    if (r0 == IMMEDIATE(0))
#line 76 "sample/undocked/inner_map.c"
        goto label_2;
        // EBPF_OP_JA pc=35 dst=r0 src=r0 offset=-20 imm=0
#line 76 "sample/undocked/inner_map.c"
    goto label_1;
#line 76 "sample/undocked/inner_map.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        lookup_update,
        "sample~1",
        "sample_ext",
        "lookup_update",
        lookup_update_maps,
        2,
        lookup_update_helpers,
        1,
        36,
        &lookup_update_program_type_guid,
        &lookup_update_attach_type_guid,
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

metadata_table_t inner_map_metadata_table = {
    sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version, _get_map_initial_values};
