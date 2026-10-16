// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from cgroup_sock_addr_socket_cookie.o

#define NO_CRT
#include "bpf2c.h"

#include <guiddef.h>
#include <wdm.h>
#include <wsk.h>

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
RTL_QUERY_REGISTRY_ROUTINE static _bpf2c_query_registry_routine;

#define metadata_table cgroup_sock_addr_socket_cookie##_metadata_table

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
         1,                 // Current Version.
         80,                // Struct size up to the last field.
         80,                // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_HASH, // Type of map.
         4,                 // Size in bytes of a map key.
         8,                 // Size in bytes of a map value.
         16,                // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         LIBBPF_PIN_NONE,   // Pinning type for the map.
         13,                // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "socket_cookie_capture_map"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 1;
}

static void
_get_global_variable_sections(
    _Outptr_result_buffer_maybenull_(*count) global_variable_section_info_t** global_variable_sections,
    _Out_ size_t* count)
{
    *global_variable_sections = NULL;
    *count = 0;
}

static helper_function_entry_t capture_bind4_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     26,
     "helper_id_26",
    },
    {
     {1, 40, 40}, // Version header.
     2,
     "helper_id_2",
    },
};

static GUID capture_bind4_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID capture_bind4_attach_type_guid = {
    0x0d7ce21a, 0x7773, 0x405c, {0x93, 0xb6, 0xd5, 0xbf, 0xb9, 0x2e, 0x74, 0xbc}};
static uint16_t capture_bind4_maps[] = {
    0,
};

#pragma code_seg(push, "cgrou~10")
static uint64_t
capture_bind4(void* context, const program_runtime_context_t* runtime_context)
#line 72 "sample/cgroup_sock_addr_socket_cookie.c"
{
#line 72 "sample/cgroup_sock_addr_socket_cookie.c"
    // Prologue.
#line 72 "sample/cgroup_sock_addr_socket_cookie.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 72 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r0 = 0;
#line 72 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r1 = 0;
#line 72 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r2 = 0;
#line 72 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r3 = 0;
#line 72 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r4 = 0;
#line 72 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r5 = 0;
#line 72 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r10 = 0;

#line 72 "sample/cgroup_sock_addr_socket_cookie.c"
    r1 = (uintptr_t)context;
#line 72 "sample/cgroup_sock_addr_socket_cookie.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_LDXH pc=0 dst=r2 src=r1 offset=40 imm=0
#line 72 "sample/cgroup_sock_addr_socket_cookie.c"
    READ_ONCE_16(r2, r1, OFFSET(40));
    // EBPF_OP_JNE_IMM pc=1 dst=r2 src=r0 offset=12 imm=7459
#line 72 "sample/cgroup_sock_addr_socket_cookie.c"
    if (r2 != IMMEDIATE(7459)) {
#line 72 "sample/cgroup_sock_addr_socket_cookie.c"
        goto label_1;
#line 72 "sample/cgroup_sock_addr_socket_cookie.c"
    }
    // EBPF_OP_MOV64_IMM pc=2 dst=r2 src=r0 offset=0 imm=1
#line 72 "sample/cgroup_sock_addr_socket_cookie.c"
    r2 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=3 dst=r10 src=r2 offset=-4 imm=0
#line 72 "sample/cgroup_sock_addr_socket_cookie.c"
    WRITE_ONCE_32(r10, (uint32_t)r2, OFFSET(-4));
    // EBPF_OP_CALL pc=4 dst=r0 src=r0 offset=0 imm=26
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[0].address);
    // EBPF_OP_STXDW pc=5 dst=r10 src=r0 offset=-16 imm=0
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    WRITE_ONCE_64(r10, (uint64_t)r0, OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=6 dst=r2 src=r10 offset=0 imm=0
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=7 dst=r2 src=r0 offset=0 imm=-4
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=8 dst=r3 src=r10 offset=0 imm=0
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=9 dst=r3 src=r0 offset=0 imm=-16
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r3 += IMMEDIATE(-16);
    // EBPF_OP_LDDW pc=10 dst=r1 src=r1 offset=0 imm=1
#line 54 "sample/cgroup_sock_addr_socket_cookie.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=12 dst=r4 src=r0 offset=0 imm=0
#line 54 "sample/cgroup_sock_addr_socket_cookie.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=2
#line 54 "sample/cgroup_sock_addr_socket_cookie.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
label_1:
    // EBPF_OP_MOV64_IMM pc=14 dst=r0 src=r0 offset=0 imm=1
#line 72 "sample/cgroup_sock_addr_socket_cookie.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=15 dst=r0 src=r0 offset=0 imm=0
#line 72 "sample/cgroup_sock_addr_socket_cookie.c"
    return r0;
#line 72 "sample/cgroup_sock_addr_socket_cookie.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t capture_bind6_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     26,
     "helper_id_26",
    },
    {
     {1, 40, 40}, // Version header.
     2,
     "helper_id_2",
    },
};

static GUID capture_bind6_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID capture_bind6_attach_type_guid = {
    0x81de64c0, 0x2973, 0x468d, {0x83, 0x82, 0x67, 0x69, 0xf0, 0x33, 0xd7, 0x59}};
static uint16_t capture_bind6_maps[] = {
    0,
};

#pragma code_seg(push, "cgroup~9")
static uint64_t
capture_bind6(void* context, const program_runtime_context_t* runtime_context)
#line 73 "sample/cgroup_sock_addr_socket_cookie.c"
{
#line 73 "sample/cgroup_sock_addr_socket_cookie.c"
    // Prologue.
#line 73 "sample/cgroup_sock_addr_socket_cookie.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 73 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r0 = 0;
#line 73 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r1 = 0;
#line 73 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r2 = 0;
#line 73 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r3 = 0;
#line 73 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r4 = 0;
#line 73 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r5 = 0;
#line 73 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r10 = 0;

#line 73 "sample/cgroup_sock_addr_socket_cookie.c"
    r1 = (uintptr_t)context;
#line 73 "sample/cgroup_sock_addr_socket_cookie.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_LDXH pc=0 dst=r2 src=r1 offset=40 imm=0
#line 73 "sample/cgroup_sock_addr_socket_cookie.c"
    READ_ONCE_16(r2, r1, OFFSET(40));
    // EBPF_OP_JNE_IMM pc=1 dst=r2 src=r0 offset=12 imm=7459
#line 73 "sample/cgroup_sock_addr_socket_cookie.c"
    if (r2 != IMMEDIATE(7459)) {
#line 73 "sample/cgroup_sock_addr_socket_cookie.c"
        goto label_1;
#line 73 "sample/cgroup_sock_addr_socket_cookie.c"
    }
    // EBPF_OP_MOV64_IMM pc=2 dst=r2 src=r0 offset=0 imm=2
#line 73 "sample/cgroup_sock_addr_socket_cookie.c"
    r2 = IMMEDIATE(2);
    // EBPF_OP_STXW pc=3 dst=r10 src=r2 offset=-4 imm=0
#line 73 "sample/cgroup_sock_addr_socket_cookie.c"
    WRITE_ONCE_32(r10, (uint32_t)r2, OFFSET(-4));
    // EBPF_OP_CALL pc=4 dst=r0 src=r0 offset=0 imm=26
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[0].address);
    // EBPF_OP_STXDW pc=5 dst=r10 src=r0 offset=-16 imm=0
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    WRITE_ONCE_64(r10, (uint64_t)r0, OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=6 dst=r2 src=r10 offset=0 imm=0
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=7 dst=r2 src=r0 offset=0 imm=-4
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=8 dst=r3 src=r10 offset=0 imm=0
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=9 dst=r3 src=r0 offset=0 imm=-16
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r3 += IMMEDIATE(-16);
    // EBPF_OP_LDDW pc=10 dst=r1 src=r1 offset=0 imm=1
#line 54 "sample/cgroup_sock_addr_socket_cookie.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=12 dst=r4 src=r0 offset=0 imm=0
#line 54 "sample/cgroup_sock_addr_socket_cookie.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=2
#line 54 "sample/cgroup_sock_addr_socket_cookie.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
label_1:
    // EBPF_OP_MOV64_IMM pc=14 dst=r0 src=r0 offset=0 imm=1
#line 73 "sample/cgroup_sock_addr_socket_cookie.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=15 dst=r0 src=r0 offset=0 imm=0
#line 73 "sample/cgroup_sock_addr_socket_cookie.c"
    return r0;
#line 73 "sample/cgroup_sock_addr_socket_cookie.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t capture_connect4_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     26,
     "helper_id_26",
    },
    {
     {1, 40, 40}, // Version header.
     2,
     "helper_id_2",
    },
};

static GUID capture_connect4_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID capture_connect4_attach_type_guid = {
    0xa82e37b1, 0xaee7, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static uint16_t capture_connect4_maps[] = {
    0,
};

#pragma code_seg(push, "cgroup~6")
static uint64_t
capture_connect4(void* context, const program_runtime_context_t* runtime_context)
#line 76 "sample/cgroup_sock_addr_socket_cookie.c"
{
#line 76 "sample/cgroup_sock_addr_socket_cookie.c"
    // Prologue.
#line 76 "sample/cgroup_sock_addr_socket_cookie.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 76 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r0 = 0;
#line 76 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r1 = 0;
#line 76 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r2 = 0;
#line 76 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r3 = 0;
#line 76 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r4 = 0;
#line 76 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r5 = 0;
#line 76 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r10 = 0;

#line 76 "sample/cgroup_sock_addr_socket_cookie.c"
    r1 = (uintptr_t)context;
#line 76 "sample/cgroup_sock_addr_socket_cookie.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_LDXH pc=0 dst=r2 src=r1 offset=40 imm=0
#line 76 "sample/cgroup_sock_addr_socket_cookie.c"
    READ_ONCE_16(r2, r1, OFFSET(40));
    // EBPF_OP_JNE_IMM pc=1 dst=r2 src=r0 offset=12 imm=7459
#line 76 "sample/cgroup_sock_addr_socket_cookie.c"
    if (r2 != IMMEDIATE(7459)) {
#line 76 "sample/cgroup_sock_addr_socket_cookie.c"
        goto label_1;
#line 76 "sample/cgroup_sock_addr_socket_cookie.c"
    }
    // EBPF_OP_MOV64_IMM pc=2 dst=r2 src=r0 offset=0 imm=5
#line 76 "sample/cgroup_sock_addr_socket_cookie.c"
    r2 = IMMEDIATE(5);
    // EBPF_OP_STXW pc=3 dst=r10 src=r2 offset=-4 imm=0
#line 76 "sample/cgroup_sock_addr_socket_cookie.c"
    WRITE_ONCE_32(r10, (uint32_t)r2, OFFSET(-4));
    // EBPF_OP_CALL pc=4 dst=r0 src=r0 offset=0 imm=26
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[0].address);
    // EBPF_OP_STXDW pc=5 dst=r10 src=r0 offset=-16 imm=0
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    WRITE_ONCE_64(r10, (uint64_t)r0, OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=6 dst=r2 src=r10 offset=0 imm=0
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=7 dst=r2 src=r0 offset=0 imm=-4
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=8 dst=r3 src=r10 offset=0 imm=0
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=9 dst=r3 src=r0 offset=0 imm=-16
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r3 += IMMEDIATE(-16);
    // EBPF_OP_LDDW pc=10 dst=r1 src=r1 offset=0 imm=1
#line 54 "sample/cgroup_sock_addr_socket_cookie.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=12 dst=r4 src=r0 offset=0 imm=0
#line 54 "sample/cgroup_sock_addr_socket_cookie.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=2
#line 54 "sample/cgroup_sock_addr_socket_cookie.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
label_1:
    // EBPF_OP_MOV64_IMM pc=14 dst=r0 src=r0 offset=0 imm=1
#line 76 "sample/cgroup_sock_addr_socket_cookie.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=15 dst=r0 src=r0 offset=0 imm=0
#line 76 "sample/cgroup_sock_addr_socket_cookie.c"
    return r0;
#line 76 "sample/cgroup_sock_addr_socket_cookie.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t capture_connect6_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     26,
     "helper_id_26",
    },
    {
     {1, 40, 40}, // Version header.
     2,
     "helper_id_2",
    },
};

static GUID capture_connect6_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID capture_connect6_attach_type_guid = {
    0xa82e37b2, 0xaee7, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static uint16_t capture_connect6_maps[] = {
    0,
};

#pragma code_seg(push, "cgroup~5")
static uint64_t
capture_connect6(void* context, const program_runtime_context_t* runtime_context)
#line 77 "sample/cgroup_sock_addr_socket_cookie.c"
{
#line 77 "sample/cgroup_sock_addr_socket_cookie.c"
    // Prologue.
#line 77 "sample/cgroup_sock_addr_socket_cookie.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 77 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r0 = 0;
#line 77 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r1 = 0;
#line 77 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r2 = 0;
#line 77 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r3 = 0;
#line 77 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r4 = 0;
#line 77 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r5 = 0;
#line 77 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r10 = 0;

#line 77 "sample/cgroup_sock_addr_socket_cookie.c"
    r1 = (uintptr_t)context;
#line 77 "sample/cgroup_sock_addr_socket_cookie.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_LDXH pc=0 dst=r2 src=r1 offset=40 imm=0
#line 77 "sample/cgroup_sock_addr_socket_cookie.c"
    READ_ONCE_16(r2, r1, OFFSET(40));
    // EBPF_OP_JNE_IMM pc=1 dst=r2 src=r0 offset=12 imm=7459
#line 77 "sample/cgroup_sock_addr_socket_cookie.c"
    if (r2 != IMMEDIATE(7459)) {
#line 77 "sample/cgroup_sock_addr_socket_cookie.c"
        goto label_1;
#line 77 "sample/cgroup_sock_addr_socket_cookie.c"
    }
    // EBPF_OP_MOV64_IMM pc=2 dst=r2 src=r0 offset=0 imm=6
#line 77 "sample/cgroup_sock_addr_socket_cookie.c"
    r2 = IMMEDIATE(6);
    // EBPF_OP_STXW pc=3 dst=r10 src=r2 offset=-4 imm=0
#line 77 "sample/cgroup_sock_addr_socket_cookie.c"
    WRITE_ONCE_32(r10, (uint32_t)r2, OFFSET(-4));
    // EBPF_OP_CALL pc=4 dst=r0 src=r0 offset=0 imm=26
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[0].address);
    // EBPF_OP_STXDW pc=5 dst=r10 src=r0 offset=-16 imm=0
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    WRITE_ONCE_64(r10, (uint64_t)r0, OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=6 dst=r2 src=r10 offset=0 imm=0
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=7 dst=r2 src=r0 offset=0 imm=-4
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=8 dst=r3 src=r10 offset=0 imm=0
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=9 dst=r3 src=r0 offset=0 imm=-16
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r3 += IMMEDIATE(-16);
    // EBPF_OP_LDDW pc=10 dst=r1 src=r1 offset=0 imm=1
#line 54 "sample/cgroup_sock_addr_socket_cookie.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=12 dst=r4 src=r0 offset=0 imm=0
#line 54 "sample/cgroup_sock_addr_socket_cookie.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=2
#line 54 "sample/cgroup_sock_addr_socket_cookie.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
label_1:
    // EBPF_OP_MOV64_IMM pc=14 dst=r0 src=r0 offset=0 imm=1
#line 77 "sample/cgroup_sock_addr_socket_cookie.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=15 dst=r0 src=r0 offset=0 imm=0
#line 77 "sample/cgroup_sock_addr_socket_cookie.c"
    return r0;
#line 77 "sample/cgroup_sock_addr_socket_cookie.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t capture_connect_authorization4_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     26,
     "helper_id_26",
    },
    {
     {1, 40, 40}, // Version header.
     2,
     "helper_id_2",
    },
};

static GUID capture_connect_authorization4_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID capture_connect_authorization4_attach_type_guid = {
    0x6076c13a, 0xf04f, 0x4ff8, {0x83, 0x80, 0x90, 0x85, 0x53, 0xf2, 0x22, 0x76}};
static uint16_t capture_connect_authorization4_maps[] = {
    0,
};

#pragma code_seg(push, "cgroup~4")
static uint64_t
capture_connect_authorization4(void* context, const program_runtime_context_t* runtime_context)
#line 78 "sample/cgroup_sock_addr_socket_cookie.c"
{
#line 78 "sample/cgroup_sock_addr_socket_cookie.c"
    // Prologue.
#line 78 "sample/cgroup_sock_addr_socket_cookie.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 78 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r0 = 0;
#line 78 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r1 = 0;
#line 78 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r2 = 0;
#line 78 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r3 = 0;
#line 78 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r4 = 0;
#line 78 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r5 = 0;
#line 78 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r10 = 0;

#line 78 "sample/cgroup_sock_addr_socket_cookie.c"
    r1 = (uintptr_t)context;
#line 78 "sample/cgroup_sock_addr_socket_cookie.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_LDXH pc=0 dst=r2 src=r1 offset=40 imm=0
#line 78 "sample/cgroup_sock_addr_socket_cookie.c"
    READ_ONCE_16(r2, r1, OFFSET(40));
    // EBPF_OP_JNE_IMM pc=1 dst=r2 src=r0 offset=12 imm=7459
#line 78 "sample/cgroup_sock_addr_socket_cookie.c"
    if (r2 != IMMEDIATE(7459)) {
#line 78 "sample/cgroup_sock_addr_socket_cookie.c"
        goto label_1;
#line 78 "sample/cgroup_sock_addr_socket_cookie.c"
    }
    // EBPF_OP_MOV64_IMM pc=2 dst=r2 src=r0 offset=0 imm=7
#line 78 "sample/cgroup_sock_addr_socket_cookie.c"
    r2 = IMMEDIATE(7);
    // EBPF_OP_STXW pc=3 dst=r10 src=r2 offset=-4 imm=0
#line 78 "sample/cgroup_sock_addr_socket_cookie.c"
    WRITE_ONCE_32(r10, (uint32_t)r2, OFFSET(-4));
    // EBPF_OP_CALL pc=4 dst=r0 src=r0 offset=0 imm=26
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[0].address);
    // EBPF_OP_STXDW pc=5 dst=r10 src=r0 offset=-16 imm=0
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    WRITE_ONCE_64(r10, (uint64_t)r0, OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=6 dst=r2 src=r10 offset=0 imm=0
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=7 dst=r2 src=r0 offset=0 imm=-4
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=8 dst=r3 src=r10 offset=0 imm=0
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=9 dst=r3 src=r0 offset=0 imm=-16
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r3 += IMMEDIATE(-16);
    // EBPF_OP_LDDW pc=10 dst=r1 src=r1 offset=0 imm=1
#line 54 "sample/cgroup_sock_addr_socket_cookie.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=12 dst=r4 src=r0 offset=0 imm=0
#line 54 "sample/cgroup_sock_addr_socket_cookie.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=2
#line 54 "sample/cgroup_sock_addr_socket_cookie.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
label_1:
    // EBPF_OP_MOV64_IMM pc=14 dst=r0 src=r0 offset=0 imm=1
#line 78 "sample/cgroup_sock_addr_socket_cookie.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=15 dst=r0 src=r0 offset=0 imm=0
#line 78 "sample/cgroup_sock_addr_socket_cookie.c"
    return r0;
#line 78 "sample/cgroup_sock_addr_socket_cookie.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t capture_connect_authorization6_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     26,
     "helper_id_26",
    },
    {
     {1, 40, 40}, // Version header.
     2,
     "helper_id_2",
    },
};

static GUID capture_connect_authorization6_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID capture_connect_authorization6_attach_type_guid = {
    0x54b0b6ed, 0x432a, 0x4674, {0x8b, 0x27, 0x8d, 0x9f, 0x5b, 0x40, 0xc6, 0x75}};
static uint16_t capture_connect_authorization6_maps[] = {
    0,
};

#pragma code_seg(push, "cgroup~3")
static uint64_t
capture_connect_authorization6(void* context, const program_runtime_context_t* runtime_context)
#line 80 "sample/cgroup_sock_addr_socket_cookie.c"
{
#line 80 "sample/cgroup_sock_addr_socket_cookie.c"
    // Prologue.
#line 80 "sample/cgroup_sock_addr_socket_cookie.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 80 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r0 = 0;
#line 80 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r1 = 0;
#line 80 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r2 = 0;
#line 80 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r3 = 0;
#line 80 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r4 = 0;
#line 80 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r5 = 0;
#line 80 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r10 = 0;

#line 80 "sample/cgroup_sock_addr_socket_cookie.c"
    r1 = (uintptr_t)context;
#line 80 "sample/cgroup_sock_addr_socket_cookie.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_LDXH pc=0 dst=r2 src=r1 offset=40 imm=0
#line 80 "sample/cgroup_sock_addr_socket_cookie.c"
    READ_ONCE_16(r2, r1, OFFSET(40));
    // EBPF_OP_JNE_IMM pc=1 dst=r2 src=r0 offset=12 imm=7459
#line 80 "sample/cgroup_sock_addr_socket_cookie.c"
    if (r2 != IMMEDIATE(7459)) {
#line 80 "sample/cgroup_sock_addr_socket_cookie.c"
        goto label_1;
#line 80 "sample/cgroup_sock_addr_socket_cookie.c"
    }
    // EBPF_OP_MOV64_IMM pc=2 dst=r2 src=r0 offset=0 imm=8
#line 80 "sample/cgroup_sock_addr_socket_cookie.c"
    r2 = IMMEDIATE(8);
    // EBPF_OP_STXW pc=3 dst=r10 src=r2 offset=-4 imm=0
#line 80 "sample/cgroup_sock_addr_socket_cookie.c"
    WRITE_ONCE_32(r10, (uint32_t)r2, OFFSET(-4));
    // EBPF_OP_CALL pc=4 dst=r0 src=r0 offset=0 imm=26
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[0].address);
    // EBPF_OP_STXDW pc=5 dst=r10 src=r0 offset=-16 imm=0
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    WRITE_ONCE_64(r10, (uint64_t)r0, OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=6 dst=r2 src=r10 offset=0 imm=0
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=7 dst=r2 src=r0 offset=0 imm=-4
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=8 dst=r3 src=r10 offset=0 imm=0
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=9 dst=r3 src=r0 offset=0 imm=-16
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r3 += IMMEDIATE(-16);
    // EBPF_OP_LDDW pc=10 dst=r1 src=r1 offset=0 imm=1
#line 54 "sample/cgroup_sock_addr_socket_cookie.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=12 dst=r4 src=r0 offset=0 imm=0
#line 54 "sample/cgroup_sock_addr_socket_cookie.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=2
#line 54 "sample/cgroup_sock_addr_socket_cookie.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
label_1:
    // EBPF_OP_MOV64_IMM pc=14 dst=r0 src=r0 offset=0 imm=1
#line 80 "sample/cgroup_sock_addr_socket_cookie.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=15 dst=r0 src=r0 offset=0 imm=0
#line 80 "sample/cgroup_sock_addr_socket_cookie.c"
    return r0;
#line 80 "sample/cgroup_sock_addr_socket_cookie.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t capture_listen4_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     26,
     "helper_id_26",
    },
    {
     {1, 40, 40}, // Version header.
     2,
     "helper_id_2",
    },
};

static GUID capture_listen4_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID capture_listen4_attach_type_guid = {
    0xe1b0cb3d, 0xd70c, 0x4ee2, {0xb2, 0x3a, 0x07, 0x42, 0xbe, 0xdb, 0x06, 0xd6}};
static uint16_t capture_listen4_maps[] = {
    0,
};

#pragma code_seg(push, "cgroup~8")
static uint64_t
capture_listen4(void* context, const program_runtime_context_t* runtime_context)
#line 74 "sample/cgroup_sock_addr_socket_cookie.c"
{
#line 74 "sample/cgroup_sock_addr_socket_cookie.c"
    // Prologue.
#line 74 "sample/cgroup_sock_addr_socket_cookie.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 74 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r0 = 0;
#line 74 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r1 = 0;
#line 74 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r2 = 0;
#line 74 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r3 = 0;
#line 74 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r4 = 0;
#line 74 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r5 = 0;
#line 74 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r10 = 0;

#line 74 "sample/cgroup_sock_addr_socket_cookie.c"
    r1 = (uintptr_t)context;
#line 74 "sample/cgroup_sock_addr_socket_cookie.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_LDXH pc=0 dst=r2 src=r1 offset=40 imm=0
#line 74 "sample/cgroup_sock_addr_socket_cookie.c"
    READ_ONCE_16(r2, r1, OFFSET(40));
    // EBPF_OP_JNE_IMM pc=1 dst=r2 src=r0 offset=12 imm=7459
#line 74 "sample/cgroup_sock_addr_socket_cookie.c"
    if (r2 != IMMEDIATE(7459)) {
#line 74 "sample/cgroup_sock_addr_socket_cookie.c"
        goto label_1;
#line 74 "sample/cgroup_sock_addr_socket_cookie.c"
    }
    // EBPF_OP_MOV64_IMM pc=2 dst=r2 src=r0 offset=0 imm=3
#line 74 "sample/cgroup_sock_addr_socket_cookie.c"
    r2 = IMMEDIATE(3);
    // EBPF_OP_STXW pc=3 dst=r10 src=r2 offset=-4 imm=0
#line 74 "sample/cgroup_sock_addr_socket_cookie.c"
    WRITE_ONCE_32(r10, (uint32_t)r2, OFFSET(-4));
    // EBPF_OP_CALL pc=4 dst=r0 src=r0 offset=0 imm=26
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[0].address);
    // EBPF_OP_STXDW pc=5 dst=r10 src=r0 offset=-16 imm=0
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    WRITE_ONCE_64(r10, (uint64_t)r0, OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=6 dst=r2 src=r10 offset=0 imm=0
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=7 dst=r2 src=r0 offset=0 imm=-4
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=8 dst=r3 src=r10 offset=0 imm=0
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=9 dst=r3 src=r0 offset=0 imm=-16
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r3 += IMMEDIATE(-16);
    // EBPF_OP_LDDW pc=10 dst=r1 src=r1 offset=0 imm=1
#line 54 "sample/cgroup_sock_addr_socket_cookie.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=12 dst=r4 src=r0 offset=0 imm=0
#line 54 "sample/cgroup_sock_addr_socket_cookie.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=2
#line 54 "sample/cgroup_sock_addr_socket_cookie.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
label_1:
    // EBPF_OP_MOV64_IMM pc=14 dst=r0 src=r0 offset=0 imm=1
#line 74 "sample/cgroup_sock_addr_socket_cookie.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=15 dst=r0 src=r0 offset=0 imm=0
#line 74 "sample/cgroup_sock_addr_socket_cookie.c"
    return r0;
#line 74 "sample/cgroup_sock_addr_socket_cookie.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t capture_listen6_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     26,
     "helper_id_26",
    },
    {
     {1, 40, 40}, // Version header.
     2,
     "helper_id_2",
    },
};

static GUID capture_listen6_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID capture_listen6_attach_type_guid = {
    0x4e72f92e, 0x5ed0, 0x4fe5, {0xb8, 0x51, 0xb1, 0x24, 0xfe, 0x14, 0x07, 0x4d}};
static uint16_t capture_listen6_maps[] = {
    0,
};

#pragma code_seg(push, "cgroup~7")
static uint64_t
capture_listen6(void* context, const program_runtime_context_t* runtime_context)
#line 75 "sample/cgroup_sock_addr_socket_cookie.c"
{
#line 75 "sample/cgroup_sock_addr_socket_cookie.c"
    // Prologue.
#line 75 "sample/cgroup_sock_addr_socket_cookie.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 75 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r0 = 0;
#line 75 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r1 = 0;
#line 75 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r2 = 0;
#line 75 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r3 = 0;
#line 75 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r4 = 0;
#line 75 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r5 = 0;
#line 75 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r10 = 0;

#line 75 "sample/cgroup_sock_addr_socket_cookie.c"
    r1 = (uintptr_t)context;
#line 75 "sample/cgroup_sock_addr_socket_cookie.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_LDXH pc=0 dst=r2 src=r1 offset=40 imm=0
#line 75 "sample/cgroup_sock_addr_socket_cookie.c"
    READ_ONCE_16(r2, r1, OFFSET(40));
    // EBPF_OP_JNE_IMM pc=1 dst=r2 src=r0 offset=12 imm=7459
#line 75 "sample/cgroup_sock_addr_socket_cookie.c"
    if (r2 != IMMEDIATE(7459)) {
#line 75 "sample/cgroup_sock_addr_socket_cookie.c"
        goto label_1;
#line 75 "sample/cgroup_sock_addr_socket_cookie.c"
    }
    // EBPF_OP_MOV64_IMM pc=2 dst=r2 src=r0 offset=0 imm=4
#line 75 "sample/cgroup_sock_addr_socket_cookie.c"
    r2 = IMMEDIATE(4);
    // EBPF_OP_STXW pc=3 dst=r10 src=r2 offset=-4 imm=0
#line 75 "sample/cgroup_sock_addr_socket_cookie.c"
    WRITE_ONCE_32(r10, (uint32_t)r2, OFFSET(-4));
    // EBPF_OP_CALL pc=4 dst=r0 src=r0 offset=0 imm=26
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[0].address);
    // EBPF_OP_STXDW pc=5 dst=r10 src=r0 offset=-16 imm=0
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    WRITE_ONCE_64(r10, (uint64_t)r0, OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=6 dst=r2 src=r10 offset=0 imm=0
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=7 dst=r2 src=r0 offset=0 imm=-4
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=8 dst=r3 src=r10 offset=0 imm=0
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=9 dst=r3 src=r0 offset=0 imm=-16
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r3 += IMMEDIATE(-16);
    // EBPF_OP_LDDW pc=10 dst=r1 src=r1 offset=0 imm=1
#line 54 "sample/cgroup_sock_addr_socket_cookie.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=12 dst=r4 src=r0 offset=0 imm=0
#line 54 "sample/cgroup_sock_addr_socket_cookie.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=2
#line 54 "sample/cgroup_sock_addr_socket_cookie.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
label_1:
    // EBPF_OP_MOV64_IMM pc=14 dst=r0 src=r0 offset=0 imm=1
#line 75 "sample/cgroup_sock_addr_socket_cookie.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=15 dst=r0 src=r0 offset=0 imm=0
#line 75 "sample/cgroup_sock_addr_socket_cookie.c"
    return r0;
#line 75 "sample/cgroup_sock_addr_socket_cookie.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t capture_recv_accept4_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     26,
     "helper_id_26",
    },
    {
     {1, 40, 40}, // Version header.
     2,
     "helper_id_2",
    },
};

static GUID capture_recv_accept4_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID capture_recv_accept4_attach_type_guid = {
    0xa82e37b3, 0xaee7, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static uint16_t capture_recv_accept4_maps[] = {
    0,
};

#pragma code_seg(push, "cgroup~2")
static uint64_t
capture_recv_accept4(void* context, const program_runtime_context_t* runtime_context)
#line 82 "sample/cgroup_sock_addr_socket_cookie.c"
{
#line 82 "sample/cgroup_sock_addr_socket_cookie.c"
    // Prologue.
#line 82 "sample/cgroup_sock_addr_socket_cookie.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 82 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r0 = 0;
#line 82 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r1 = 0;
#line 82 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r2 = 0;
#line 82 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r3 = 0;
#line 82 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r4 = 0;
#line 82 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r5 = 0;
#line 82 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r10 = 0;

#line 82 "sample/cgroup_sock_addr_socket_cookie.c"
    r1 = (uintptr_t)context;
#line 82 "sample/cgroup_sock_addr_socket_cookie.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_LDXH pc=0 dst=r2 src=r1 offset=40 imm=0
#line 82 "sample/cgroup_sock_addr_socket_cookie.c"
    READ_ONCE_16(r2, r1, OFFSET(40));
    // EBPF_OP_JNE_IMM pc=1 dst=r2 src=r0 offset=12 imm=7459
#line 82 "sample/cgroup_sock_addr_socket_cookie.c"
    if (r2 != IMMEDIATE(7459)) {
#line 82 "sample/cgroup_sock_addr_socket_cookie.c"
        goto label_1;
#line 82 "sample/cgroup_sock_addr_socket_cookie.c"
    }
    // EBPF_OP_MOV64_IMM pc=2 dst=r2 src=r0 offset=0 imm=9
#line 82 "sample/cgroup_sock_addr_socket_cookie.c"
    r2 = IMMEDIATE(9);
    // EBPF_OP_STXW pc=3 dst=r10 src=r2 offset=-4 imm=0
#line 82 "sample/cgroup_sock_addr_socket_cookie.c"
    WRITE_ONCE_32(r10, (uint32_t)r2, OFFSET(-4));
    // EBPF_OP_CALL pc=4 dst=r0 src=r0 offset=0 imm=26
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[0].address);
    // EBPF_OP_STXDW pc=5 dst=r10 src=r0 offset=-16 imm=0
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    WRITE_ONCE_64(r10, (uint64_t)r0, OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=6 dst=r2 src=r10 offset=0 imm=0
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=7 dst=r2 src=r0 offset=0 imm=-4
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=8 dst=r3 src=r10 offset=0 imm=0
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=9 dst=r3 src=r0 offset=0 imm=-16
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r3 += IMMEDIATE(-16);
    // EBPF_OP_LDDW pc=10 dst=r1 src=r1 offset=0 imm=1
#line 54 "sample/cgroup_sock_addr_socket_cookie.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=12 dst=r4 src=r0 offset=0 imm=0
#line 54 "sample/cgroup_sock_addr_socket_cookie.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=2
#line 54 "sample/cgroup_sock_addr_socket_cookie.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
label_1:
    // EBPF_OP_MOV64_IMM pc=14 dst=r0 src=r0 offset=0 imm=1
#line 82 "sample/cgroup_sock_addr_socket_cookie.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=15 dst=r0 src=r0 offset=0 imm=0
#line 82 "sample/cgroup_sock_addr_socket_cookie.c"
    return r0;
#line 82 "sample/cgroup_sock_addr_socket_cookie.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t capture_recv_accept6_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     26,
     "helper_id_26",
    },
    {
     {1, 40, 40}, // Version header.
     2,
     "helper_id_2",
    },
};

static GUID capture_recv_accept6_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID capture_recv_accept6_attach_type_guid = {
    0xa82e37b4, 0xaee7, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static uint16_t capture_recv_accept6_maps[] = {
    0,
};

#pragma code_seg(push, "cgroup~1")
static uint64_t
capture_recv_accept6(void* context, const program_runtime_context_t* runtime_context)
#line 83 "sample/cgroup_sock_addr_socket_cookie.c"
{
#line 83 "sample/cgroup_sock_addr_socket_cookie.c"
    // Prologue.
#line 83 "sample/cgroup_sock_addr_socket_cookie.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 83 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r0 = 0;
#line 83 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r1 = 0;
#line 83 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r2 = 0;
#line 83 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r3 = 0;
#line 83 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r4 = 0;
#line 83 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r5 = 0;
#line 83 "sample/cgroup_sock_addr_socket_cookie.c"
    register uint64_t r10 = 0;

#line 83 "sample/cgroup_sock_addr_socket_cookie.c"
    r1 = (uintptr_t)context;
#line 83 "sample/cgroup_sock_addr_socket_cookie.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_LDXH pc=0 dst=r2 src=r1 offset=40 imm=0
#line 83 "sample/cgroup_sock_addr_socket_cookie.c"
    READ_ONCE_16(r2, r1, OFFSET(40));
    // EBPF_OP_JNE_IMM pc=1 dst=r2 src=r0 offset=12 imm=7459
#line 83 "sample/cgroup_sock_addr_socket_cookie.c"
    if (r2 != IMMEDIATE(7459)) {
#line 83 "sample/cgroup_sock_addr_socket_cookie.c"
        goto label_1;
#line 83 "sample/cgroup_sock_addr_socket_cookie.c"
    }
    // EBPF_OP_MOV64_IMM pc=2 dst=r2 src=r0 offset=0 imm=10
#line 83 "sample/cgroup_sock_addr_socket_cookie.c"
    r2 = IMMEDIATE(10);
    // EBPF_OP_STXW pc=3 dst=r10 src=r2 offset=-4 imm=0
#line 83 "sample/cgroup_sock_addr_socket_cookie.c"
    WRITE_ONCE_32(r10, (uint32_t)r2, OFFSET(-4));
    // EBPF_OP_CALL pc=4 dst=r0 src=r0 offset=0 imm=26
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[0].address);
    // EBPF_OP_STXDW pc=5 dst=r10 src=r0 offset=-16 imm=0
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    WRITE_ONCE_64(r10, (uint64_t)r0, OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=6 dst=r2 src=r10 offset=0 imm=0
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=7 dst=r2 src=r0 offset=0 imm=-4
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=8 dst=r3 src=r10 offset=0 imm=0
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=9 dst=r3 src=r0 offset=0 imm=-16
#line 53 "sample/cgroup_sock_addr_socket_cookie.c"
    r3 += IMMEDIATE(-16);
    // EBPF_OP_LDDW pc=10 dst=r1 src=r1 offset=0 imm=1
#line 54 "sample/cgroup_sock_addr_socket_cookie.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=12 dst=r4 src=r0 offset=0 imm=0
#line 54 "sample/cgroup_sock_addr_socket_cookie.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=2
#line 54 "sample/cgroup_sock_addr_socket_cookie.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
label_1:
    // EBPF_OP_MOV64_IMM pc=14 dst=r0 src=r0 offset=0 imm=1
#line 83 "sample/cgroup_sock_addr_socket_cookie.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=15 dst=r0 src=r0 offset=0 imm=0
#line 83 "sample/cgroup_sock_addr_socket_cookie.c"
    return r0;
#line 83 "sample/cgroup_sock_addr_socket_cookie.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        {1, 154, 160}, // Version header.
        capture_bind4,
        "cgrou~10",
        "cgroup/bind4",
        "capture_bind4",
        capture_bind4_maps,
        1,
        capture_bind4_helpers,
        2,
        16,
        &capture_bind4_program_type_guid,
        &capture_bind4_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        capture_bind6,
        "cgroup~9",
        "cgroup/bind6",
        "capture_bind6",
        capture_bind6_maps,
        1,
        capture_bind6_helpers,
        2,
        16,
        &capture_bind6_program_type_guid,
        &capture_bind6_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        capture_connect4,
        "cgroup~6",
        "cgroup/connect4",
        "capture_connect4",
        capture_connect4_maps,
        1,
        capture_connect4_helpers,
        2,
        16,
        &capture_connect4_program_type_guid,
        &capture_connect4_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        capture_connect6,
        "cgroup~5",
        "cgroup/connect6",
        "capture_connect6",
        capture_connect6_maps,
        1,
        capture_connect6_helpers,
        2,
        16,
        &capture_connect6_program_type_guid,
        &capture_connect6_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        capture_connect_authorization4,
        "cgroup~4",
        "cgroup/connect_authorization4",
        "capture_connect_authorization4",
        capture_connect_authorization4_maps,
        1,
        capture_connect_authorization4_helpers,
        2,
        16,
        &capture_connect_authorization4_program_type_guid,
        &capture_connect_authorization4_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        capture_connect_authorization6,
        "cgroup~3",
        "cgroup/connect_authorization6",
        "capture_connect_authorization6",
        capture_connect_authorization6_maps,
        1,
        capture_connect_authorization6_helpers,
        2,
        16,
        &capture_connect_authorization6_program_type_guid,
        &capture_connect_authorization6_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        capture_listen4,
        "cgroup~8",
        "cgroup/listen4",
        "capture_listen4",
        capture_listen4_maps,
        1,
        capture_listen4_helpers,
        2,
        16,
        &capture_listen4_program_type_guid,
        &capture_listen4_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        capture_listen6,
        "cgroup~7",
        "cgroup/listen6",
        "capture_listen6",
        capture_listen6_maps,
        1,
        capture_listen6_helpers,
        2,
        16,
        &capture_listen6_program_type_guid,
        &capture_listen6_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        capture_recv_accept4,
        "cgroup~2",
        "cgroup/recv_accept4",
        "capture_recv_accept4",
        capture_recv_accept4_maps,
        1,
        capture_recv_accept4_helpers,
        2,
        16,
        &capture_recv_accept4_program_type_guid,
        &capture_recv_accept4_attach_type_guid,
    },
    {
        0,
        {1, 154, 160}, // Version header.
        capture_recv_accept6,
        "cgroup~1",
        "cgroup/recv_accept6",
        "capture_recv_accept6",
        capture_recv_accept6_maps,
        1,
        capture_recv_accept6_helpers,
        2,
        16,
        &capture_recv_accept6_program_type_guid,
        &capture_recv_accept6_attach_type_guid,
    },
};
#pragma data_seg(pop)

static void
_get_programs(_Outptr_result_buffer_(*count) program_entry_t** programs, _Out_ size_t* count)
{
    *programs = _programs;
    *count = 10;
}

static void
_get_version(_Out_ bpf2c_version_t* version)
{
    version->major = 1;
    version->minor = 7;
    version->revision = 0;
}

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = NULL;
    *count = 0;
}

metadata_table_t cgroup_sock_addr_socket_cookie_metadata_table = {
    sizeof(metadata_table_t),
    _get_programs,
    _get_maps,
    _get_hash,
    _get_version,
    _get_map_initial_values,
    _get_global_variable_sections,
};
