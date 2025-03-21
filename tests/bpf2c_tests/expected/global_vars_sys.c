// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from global_vars.o

#define NO_CRT
#include "bpf2c.h"

#include <guiddef.h>
#include <wdm.h>
#include <wsk.h>

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
RTL_QUERY_REGISTRY_ROUTINE static _bpf2c_query_registry_routine;

#define metadata_table global_vars##_metadata_table

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
     NULL}};

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

    status = NmrClientAttachProvider(
        nmr_binding_handle, client_context, &metadata_table, &provider_binding_context, &provider_dispatch_table);
    if (status != STATUS_SUCCESS) {
        goto Done;
    }
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
    {
     {0, 0},
     {
         1,                  // Current Version.
         80,                 // Struct size up to the last field.
         80,                 // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_ARRAY, // Type of map.
         4,                  // Size in bytes of a map key.
         4,                  // Size in bytes of a map value.
         1,                  // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         LIBBPF_PIN_NONE,    // Pinning type for the map.
         26,                 // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "global_.rodata"},
    {
     {0, 0},
     {
         1,                  // Current Version.
         80,                 // Struct size up to the last field.
         80,                 // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_ARRAY, // Type of map.
         4,                  // Size in bytes of a map key.
         8,                  // Size in bytes of a map value.
         1,                  // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         LIBBPF_PIN_NONE,    // Pinning type for the map.
         24,                 // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "global_.data"},
    {
     {0, 0},
     {
         1,                  // Current Version.
         80,                 // Struct size up to the last field.
         80,                 // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_ARRAY, // Type of map.
         4,                  // Size in bytes of a map key.
         4,                  // Size in bytes of a map value.
         1,                  // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         LIBBPF_PIN_NONE,    // Pinning type for the map.
         23,                 // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "global_.bss"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 3;
}

const char global__rodata_initial_data[] = {10, 0, 0, 0};

const char global__data_initial_data[] = {20, 0, 0, 0, 40, 0, 0, 0};

const char global__bss_initial_data[] = {0, 0, 0, 0};

#pragma data_seg(push, "global_variables")
static global_variable_section_info_t _global_variable_sections[] = {
    {
        .header = {1, 48, 48},
        .name = "global_.rodata",
        .size = 4,
        .initial_data = &global__rodata_initial_data,
    },
    {
        .header = {1, 48, 48},
        .name = "global_.data",
        .size = 8,
        .initial_data = &global__data_initial_data,
    },
    {
        .header = {1, 48, 48},
        .name = "global_.bss",
        .size = 4,
        .initial_data = &global__bss_initial_data,
    },
};
#pragma data_seg(pop)

static void
_get_global_variable_sections(
    _Outptr_result_buffer_maybenull_(*count) global_variable_section_info_t** global_variable_sections,
    _Out_ size_t* count)
{
    *global_variable_sections = _global_variable_sections;
    *count = 3;
}

static GUID GlobalVariableTest_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID GlobalVariableTest_attach_type_guid = {
    0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static uint16_t GlobalVariableTest_maps[] = {
    0,
    1,
    2,
};

#pragma code_seg(push, "sample~1")
static uint64_t
GlobalVariableTest(void* context, const program_runtime_context_t* runtime_context)
#line 30 "sample/undocked/global_vars.c"
{
#line 30 "sample/undocked/global_vars.c"
    // Prologue.
#line 30 "sample/undocked/global_vars.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 30 "sample/undocked/global_vars.c"
    register uint64_t r0 = 0;
#line 30 "sample/undocked/global_vars.c"
    register uint64_t r1 = 0;
#line 30 "sample/undocked/global_vars.c"
    register uint64_t r2 = 0;
#line 30 "sample/undocked/global_vars.c"
    register uint64_t r3 = 0;
#line 30 "sample/undocked/global_vars.c"
    register uint64_t r10 = 0;

#line 30 "sample/undocked/global_vars.c"
    r1 = (uintptr_t)context;
#line 30 "sample/undocked/global_vars.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_LDDW pc=0 dst=r1 src=r2 offset=0 imm=3
#line 30 "sample/undocked/global_vars.c"
    r1 = POINTER(runtime_context->global_variable_section_data[0].address_of_map_value + 0);
    // EBPF_OP_LDXW pc=2 dst=r1 src=r1 offset=0 imm=0
#line 30 "sample/undocked/global_vars.c"
    r1 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(0));
    // EBPF_OP_LDDW pc=3 dst=r2 src=r2 offset=0 imm=2
#line 30 "sample/undocked/global_vars.c"
    r2 = POINTER(runtime_context->global_variable_section_data[1].address_of_map_value + 0);
    // EBPF_OP_LDXW pc=5 dst=r2 src=r2 offset=0 imm=0
#line 30 "sample/undocked/global_vars.c"
    r2 = *(uint32_t*)(uintptr_t)(r2 + OFFSET(0));
    // EBPF_OP_ADD64_REG pc=6 dst=r2 src=r1 offset=0 imm=0
#line 30 "sample/undocked/global_vars.c"
    r2 += r1;
    // EBPF_OP_LDDW pc=7 dst=r1 src=r2 offset=0 imm=1
#line 30 "sample/undocked/global_vars.c"
    r1 = POINTER(runtime_context->global_variable_section_data[2].address_of_map_value + 0);
    // EBPF_OP_STXW pc=9 dst=r1 src=r2 offset=0 imm=0
#line 30 "sample/undocked/global_vars.c"
    *(uint32_t*)(uintptr_t)(r1 + OFFSET(0)) = (uint32_t)r2;
    // EBPF_OP_LDDW pc=10 dst=r2 src=r2 offset=0 imm=2
#line 31 "sample/undocked/global_vars.c"
    r2 = POINTER(runtime_context->global_variable_section_data[1].address_of_map_value + 4);
    // EBPF_OP_LDXW pc=12 dst=r2 src=r2 offset=0 imm=0
#line 31 "sample/undocked/global_vars.c"
    r2 = *(uint32_t*)(uintptr_t)(r2 + OFFSET(0));
    // EBPF_OP_LDXW pc=13 dst=r3 src=r1 offset=0 imm=0
#line 31 "sample/undocked/global_vars.c"
    r3 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(0));
    // EBPF_OP_ADD64_REG pc=14 dst=r3 src=r2 offset=0 imm=0
#line 31 "sample/undocked/global_vars.c"
    r3 += r2;
    // EBPF_OP_STXW pc=15 dst=r1 src=r3 offset=0 imm=0
#line 31 "sample/undocked/global_vars.c"
    *(uint32_t*)(uintptr_t)(r1 + OFFSET(0)) = (uint32_t)r3;
    // EBPF_OP_MOV64_IMM pc=16 dst=r0 src=r0 offset=0 imm=0
#line 32 "sample/undocked/global_vars.c"
    r0 = IMMEDIATE(0);
    // EBPF_OP_EXIT pc=17 dst=r0 src=r0 offset=0 imm=0
#line 32 "sample/undocked/global_vars.c"
    return r0;
#line 30 "sample/undocked/global_vars.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        {1, 144, 144}, // Version header.
        GlobalVariableTest,
        "sample~1",
        "sample_ext",
        "GlobalVariableTest",
        GlobalVariableTest_maps,
        3,
        NULL,
        0,
        18,
        &GlobalVariableTest_program_type_guid,
        &GlobalVariableTest_attach_type_guid,
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
    version->minor = 21;
    version->revision = 0;
}

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = NULL;
    *count = 0;
}

metadata_table_t global_vars_metadata_table = {
    sizeof(metadata_table_t),
    _get_programs,
    _get_maps,
    _get_hash,
    _get_version,
    _get_map_initial_values,
    _get_global_variable_sections,
};
