// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from btf_resolved.o

#define NO_CRT
#include "bpf2c.h"

#include <guiddef.h>
#include <wdm.h>
#include <wsk.h>

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
RTL_QUERY_REGISTRY_ROUTINE static _bpf2c_query_registry_routine;

#define metadata_table btf_resolved##_metadata_table

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

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = NULL;
    *count = 0;
}

static void
_get_global_variable_sections(
    _Outptr_result_buffer_maybenull_(*count) global_variable_section_info_t** global_variable_sections,
    _Out_ size_t* count)
{
    *global_variable_sections = NULL;
    *count = 0;
}

static btf_resolved_function_entry_t func_btf_resolved_functions[] = {
    {
     0,
     {2, 84, 88}, // Version header.
     "sample_ebpf_extension_btf_lookup",
     {0x8f6c1f83, 0xce4c, 0x4b58, {0x8b, 0x91, 0x65, 0x4a, 0x29, 0xe2, 0x3b, 0x7c}},
     0,
     {
         1,
         9,
         2,
         0,
         0,
     },
     0,
    },
};

static GUID func_program_type_guid = {0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID func_attach_type_guid = {0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
#pragma code_seg(push, "sample~1")
static uint64_t
func(void* context, const program_runtime_context_t* runtime_context)
#line 9 "sample/undocked/btf_resolved.c"
{
#line 9 "sample/undocked/btf_resolved.c"
    // Prologue.
#line 9 "sample/undocked/btf_resolved.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 9 "sample/undocked/btf_resolved.c"
    register uint64_t r0 = 0;
#line 9 "sample/undocked/btf_resolved.c"
    register uint64_t r1 = 0;
#line 9 "sample/undocked/btf_resolved.c"
    register uint64_t r2 = 0;
#line 9 "sample/undocked/btf_resolved.c"
    register uint64_t r3 = 0;
#line 9 "sample/undocked/btf_resolved.c"
    register uint64_t r4 = 0;
#line 9 "sample/undocked/btf_resolved.c"
    register uint64_t r5 = 0;
#line 9 "sample/undocked/btf_resolved.c"
    register uint64_t r10 = 0;

#line 9 "sample/undocked/btf_resolved.c"
    r1 = (uintptr_t)context;
#line 9 "sample/undocked/btf_resolved.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r2 src=r0 offset=0 imm=0
#line 9 "sample/undocked/btf_resolved.c"
    r2 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=1 dst=r10 src=r2 offset=-8 imm=0
#line 11 "sample/undocked/btf_resolved.c"
    WRITE_ONCE_64(r10, (uint64_t)r2, OFFSET(-8));
    // EBPF_OP_LDXW pc=2 dst=r1 src=r1 offset=16 imm=0
#line 12 "sample/undocked/btf_resolved.c"
    READ_ONCE_32(r1, r1, OFFSET(16));
    // EBPF_OP_MOV64_REG pc=3 dst=r2 src=r10 offset=0 imm=0
#line 12 "sample/undocked/btf_resolved.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=4 dst=r2 src=r0 offset=0 imm=-8
#line 12 "sample/undocked/btf_resolved.c"
    r2 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_IMM pc=5 dst=r3 src=r0 offset=0 imm=8
#line 12 "sample/undocked/btf_resolved.c"
    r3 = IMMEDIATE(8);
    // EBPF_OP_CALL pc=6 dst=r0 src=r2 offset=0 imm=1
#line 12 "sample/undocked/btf_resolved.c"
    r0 = ((helper_function_t)runtime_context->btf_resolved_function_data[0].address)(r1, r2, r3, r4, r5, context);
    // EBPF_OP_EXIT pc=7 dst=r0 src=r0 offset=0 imm=0
#line 12 "sample/undocked/btf_resolved.c"
    return r0;
#line 9 "sample/undocked/btf_resolved.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        .zero = 0,
        .header = {1, 144, 160}, // Version header.
        .function = func,
        .pe_section_name = "sample~1",
        .section_name = "sample_ext",
        .program_name = "func",
        .referenced_map_indices = NULL,
        .referenced_map_count = 0,
        .helpers = NULL,
        .helper_count = 0,
        .bpf_instruction_count = 8,
        .program_type = &func_program_type_guid,
        .expected_attach_type = &func_attach_type_guid,
        .btf_resolved_functions = func_btf_resolved_functions,
        .btf_resolved_function_count = 1,
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
    version->major = 1;
    version->minor = 4;
    version->revision = 0;
}

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = NULL;
    *count = 0;
}

metadata_table_t btf_resolved_metadata_table = {
    sizeof(metadata_table_t),
    _get_programs,
    _get_maps,
    _get_hash,
    _get_version,
    _get_map_initial_values,
    _get_global_variable_sections,
};
