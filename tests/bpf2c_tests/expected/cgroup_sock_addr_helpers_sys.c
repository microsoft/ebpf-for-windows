// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from cgroup_sock_addr_helpers.o

#define NO_CRT
#include "bpf2c.h"

#include <guiddef.h>
#include <wdm.h>
#include <wsk.h>

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
RTL_QUERY_REGISTRY_ROUTINE static _bpf2c_query_registry_routine;

#define metadata_table cgroup_sock_addr_helpers##_metadata_table

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
         32,                // Size in bytes of a map value.
         1000,              // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         LIBBPF_PIN_NONE,   // Pinning type for the map.
         15,                // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "network_context_map"},
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
         1,                 // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         LIBBPF_PIN_NONE,   // Pinning type for the map.
         18,                // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "connection_count_map"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 2;
}

static void
_get_global_variable_sections(
    _Outptr_result_buffer_maybenull_(*count) global_variable_section_info_t** global_variable_sections,
    _Out_ size_t* count)
{
    *global_variable_sections = NULL;
    *count = 0;
}

static helper_function_entry_t conditional_authorization_v4_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     65538,
     "helper_id_65538",
    },
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     2,
     "helper_id_2",
    },
};

static GUID conditional_authorization_v4_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID conditional_authorization_v4_attach_type_guid = {
    0x6076c13a, 0xf04f, 0x4ff8, {0x83, 0x80, 0x90, 0x85, 0x53, 0xf2, 0x22, 0x76}};
static uint16_t conditional_authorization_v4_maps[] = {
    1,
};

#pragma code_seg(push, "cgroup~3")
static uint64_t
conditional_authorization_v4(void* context, const program_runtime_context_t* runtime_context)
#line 53 "sample/cgroup_sock_addr_helpers.c"
{
#line 53 "sample/cgroup_sock_addr_helpers.c"
    // Prologue.
#line 53 "sample/cgroup_sock_addr_helpers.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 53 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r0 = 0;
#line 53 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r1 = 0;
#line 53 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r2 = 0;
#line 53 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r3 = 0;
#line 53 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r4 = 0;
#line 53 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r5 = 0;
#line 53 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r6 = 0;
#line 53 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r10 = 0;

#line 53 "sample/cgroup_sock_addr_helpers.c"
    r1 = (uintptr_t)context;
#line 53 "sample/cgroup_sock_addr_helpers.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r6 src=r0 offset=0 imm=1
#line 53 "sample/cgroup_sock_addr_helpers.c"
    r6 = IMMEDIATE(1);
    // EBPF_OP_LDXW pc=1 dst=r2 src=r1 offset=44 imm=0
#line 58 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_32(r2, r1, OFFSET(44));
    // EBPF_OP_JNE_IMM pc=2 dst=r2 src=r0 offset=37 imm=6
#line 58 "sample/cgroup_sock_addr_helpers.c"
    if (r2 != IMMEDIATE(6)) {
#line 58 "sample/cgroup_sock_addr_helpers.c"
        goto label_2;
#line 58 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_MOV64_IMM pc=3 dst=r6 src=r0 offset=0 imm=0
#line 63 "sample/cgroup_sock_addr_helpers.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=4 dst=r10 src=r6 offset=-8 imm=0
#line 63 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r6, OFFSET(-8));
    // EBPF_OP_STXDW pc=5 dst=r10 src=r6 offset=-16 imm=0
#line 63 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r6, OFFSET(-16));
    // EBPF_OP_STXDW pc=6 dst=r10 src=r6 offset=-24 imm=0
#line 63 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r6, OFFSET(-24));
    // EBPF_OP_STXDW pc=7 dst=r10 src=r6 offset=-32 imm=0
#line 63 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r6, OFFSET(-32));
    // EBPF_OP_MOV64_REG pc=8 dst=r2 src=r10 offset=0 imm=0
#line 63 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=9 dst=r2 src=r0 offset=0 imm=-32
#line 66 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-32);
    // EBPF_OP_MOV64_IMM pc=10 dst=r3 src=r0 offset=0 imm=32
#line 66 "sample/cgroup_sock_addr_helpers.c"
    r3 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=11 dst=r0 src=r0 offset=0 imm=65538
#line 66 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LSH64_IMM pc=12 dst=r0 src=r0 offset=0 imm=32
#line 66 "sample/cgroup_sock_addr_helpers.c"
    r0 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=13 dst=r0 src=r0 offset=0 imm=32
#line 66 "sample/cgroup_sock_addr_helpers.c"
    r0 = (int64_t)r0 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_REG pc=14 dst=r6 src=r0 offset=25 imm=0
#line 63 "sample/cgroup_sock_addr_helpers.c"
    if ((int64_t)r6 > (int64_t)r0) {
#line 63 "sample/cgroup_sock_addr_helpers.c"
        goto label_2;
#line 63 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_LDXW pc=15 dst=r1 src=r10 offset=-28 imm=0
#line 67 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_32(r1, r10, OFFSET(-28));
    // EBPF_OP_JEQ_IMM pc=16 dst=r1 src=r0 offset=23 imm=23
#line 67 "sample/cgroup_sock_addr_helpers.c"
    if (r1 == IMMEDIATE(23)) {
#line 67 "sample/cgroup_sock_addr_helpers.c"
        goto label_2;
#line 67 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_LDXW pc=17 dst=r1 src=r10 offset=-24 imm=0
#line 67 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_32(r1, r10, OFFSET(-24));
    // EBPF_OP_MOV64_IMM pc=18 dst=r6 src=r0 offset=0 imm=1
#line 67 "sample/cgroup_sock_addr_helpers.c"
    r6 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=19 dst=r1 src=r0 offset=20 imm=0
#line 67 "sample/cgroup_sock_addr_helpers.c"
    if (r1 == IMMEDIATE(0)) {
#line 67 "sample/cgroup_sock_addr_helpers.c"
        goto label_2;
#line 67 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_MOV64_IMM pc=20 dst=r1 src=r0 offset=0 imm=100
#line 67 "sample/cgroup_sock_addr_helpers.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXW pc=21 dst=r10 src=r1 offset=-36 imm=0
#line 74 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-36));
    // EBPF_OP_STXDW pc=22 dst=r10 src=r6 offset=-48 imm=0
#line 74 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r6, OFFSET(-48));
    // EBPF_OP_MOV64_REG pc=23 dst=r2 src=r10 offset=0 imm=0
#line 74 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=24 dst=r2 src=r0 offset=0 imm=-36
#line 74 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-36);
    // EBPF_OP_LDDW pc=25 dst=r1 src=r1 offset=0 imm=2
#line 74 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=27 dst=r0 src=r0 offset=0 imm=1
#line 74 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_JEQ_IMM pc=28 dst=r0 src=r0 offset=3 imm=0
#line 74 "sample/cgroup_sock_addr_helpers.c"
    if (r0 == IMMEDIATE(0)) {
#line 74 "sample/cgroup_sock_addr_helpers.c"
        goto label_1;
#line 74 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_LDXDW pc=29 dst=r1 src=r0 offset=0 imm=0
#line 77 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_64(r1, r0, OFFSET(0));
    // EBPF_OP_ADD64_IMM pc=30 dst=r1 src=r0 offset=0 imm=1
#line 78 "sample/cgroup_sock_addr_helpers.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXDW pc=31 dst=r10 src=r1 offset=-48 imm=0
#line 78 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
label_1:
    // EBPF_OP_MOV64_REG pc=32 dst=r2 src=r10 offset=0 imm=0
#line 74 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=33 dst=r2 src=r0 offset=0 imm=-36
#line 79 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-36);
    // EBPF_OP_MOV64_REG pc=34 dst=r3 src=r10 offset=0 imm=0
#line 79 "sample/cgroup_sock_addr_helpers.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=35 dst=r3 src=r0 offset=0 imm=-48
#line 79 "sample/cgroup_sock_addr_helpers.c"
    r3 += IMMEDIATE(-48);
    // EBPF_OP_LDDW pc=36 dst=r1 src=r1 offset=0 imm=2
#line 80 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_MOV64_IMM pc=38 dst=r4 src=r0 offset=0 imm=0
#line 81 "sample/cgroup_sock_addr_helpers.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=39 dst=r0 src=r0 offset=0 imm=2
#line 81 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
label_2:
    // EBPF_OP_MOV64_REG pc=40 dst=r0 src=r6 offset=0 imm=0
#line 81 "sample/cgroup_sock_addr_helpers.c"
    r0 = r6;
    // EBPF_OP_EXIT pc=41 dst=r0 src=r0 offset=0 imm=0
#line 83 "sample/cgroup_sock_addr_helpers.c"
    return r0;
#line 53 "sample/cgroup_sock_addr_helpers.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t test_recv_accept_helpers_v4_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     65538,
     "helper_id_65538",
    },
    {
     {1, 40, 40}, // Version header.
     2,
     "helper_id_2",
    },
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
};

static GUID test_recv_accept_helpers_v4_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID test_recv_accept_helpers_v4_attach_type_guid = {
    0xa82e37b3, 0xaee7, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static uint16_t test_recv_accept_helpers_v4_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "cgroup~1")
static uint64_t
test_recv_accept_helpers_v4(void* context, const program_runtime_context_t* runtime_context)
#line 175 "sample/cgroup_sock_addr_helpers.c"
{
#line 175 "sample/cgroup_sock_addr_helpers.c"
    // Prologue.
#line 175 "sample/cgroup_sock_addr_helpers.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 175 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r0 = 0;
#line 175 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r1 = 0;
#line 175 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r2 = 0;
#line 175 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r3 = 0;
#line 175 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r4 = 0;
#line 175 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r5 = 0;
#line 175 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r6 = 0;
#line 175 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r10 = 0;

#line 175 "sample/cgroup_sock_addr_helpers.c"
    r1 = (uintptr_t)context;
#line 175 "sample/cgroup_sock_addr_helpers.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r6 src=r0 offset=0 imm=1
#line 175 "sample/cgroup_sock_addr_helpers.c"
    r6 = IMMEDIATE(1);
    // EBPF_OP_LDXW pc=1 dst=r2 src=r1 offset=44 imm=0
#line 179 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_32(r2, r1, OFFSET(44));
    // EBPF_OP_JNE_IMM pc=2 dst=r2 src=r0 offset=46 imm=6
#line 179 "sample/cgroup_sock_addr_helpers.c"
    if (r2 != IMMEDIATE(6)) {
#line 179 "sample/cgroup_sock_addr_helpers.c"
        goto label_2;
#line 179 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_LDXH pc=3 dst=r2 src=r1 offset=40 imm=0
#line 183 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_16(r2, r1, OFFSET(40));
    // EBPF_OP_LSH64_IMM pc=4 dst=r2 src=r0 offset=0 imm=16
#line 183 "sample/cgroup_sock_addr_helpers.c"
    r2 <<= (IMMEDIATE(16) & 63);
    // EBPF_OP_LDXW pc=5 dst=r3 src=r1 offset=24 imm=0
#line 183 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_32(r3, r1, OFFSET(24));
    // EBPF_OP_XOR64_REG pc=6 dst=r2 src=r3 offset=0 imm=0
#line 183 "sample/cgroup_sock_addr_helpers.c"
    r2 ^= r3;
    // EBPF_OP_STXW pc=7 dst=r10 src=r2 offset=-4 imm=0
#line 183 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r2, OFFSET(-4));
    // EBPF_OP_MOV64_IMM pc=8 dst=r6 src=r0 offset=0 imm=0
#line 183 "sample/cgroup_sock_addr_helpers.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=9 dst=r10 src=r6 offset=-40 imm=0
#line 185 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r6, OFFSET(-40));
    // EBPF_OP_STXDW pc=10 dst=r10 src=r6 offset=-32 imm=0
#line 185 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r6, OFFSET(-32));
    // EBPF_OP_STXDW pc=11 dst=r10 src=r6 offset=-24 imm=0
#line 185 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r6, OFFSET(-24));
    // EBPF_OP_STXDW pc=12 dst=r10 src=r6 offset=-16 imm=0
#line 185 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r6, OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=13 dst=r2 src=r10 offset=0 imm=0
#line 185 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=14 dst=r2 src=r0 offset=0 imm=-40
#line 183 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-40);
    // EBPF_OP_MOV64_IMM pc=15 dst=r3 src=r0 offset=0 imm=32
#line 186 "sample/cgroup_sock_addr_helpers.c"
    r3 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=16 dst=r0 src=r0 offset=0 imm=65538
#line 186 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LSH64_IMM pc=17 dst=r0 src=r0 offset=0 imm=32
#line 186 "sample/cgroup_sock_addr_helpers.c"
    r0 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=18 dst=r0 src=r0 offset=0 imm=32
#line 186 "sample/cgroup_sock_addr_helpers.c"
    r0 = (int64_t)r0 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_REG pc=19 dst=r6 src=r0 offset=29 imm=0
#line 186 "sample/cgroup_sock_addr_helpers.c"
    if ((int64_t)r6 > (int64_t)r0) {
#line 186 "sample/cgroup_sock_addr_helpers.c"
        goto label_2;
#line 186 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_MOV64_REG pc=20 dst=r2 src=r10 offset=0 imm=0
#line 186 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=21 dst=r2 src=r0 offset=0 imm=-4
#line 191 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=22 dst=r3 src=r10 offset=0 imm=0
#line 191 "sample/cgroup_sock_addr_helpers.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r3 src=r0 offset=0 imm=-40
#line 191 "sample/cgroup_sock_addr_helpers.c"
    r3 += IMMEDIATE(-40);
    // EBPF_OP_LDDW pc=24 dst=r1 src=r1 offset=0 imm=1
#line 191 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=26 dst=r4 src=r0 offset=0 imm=0
#line 191 "sample/cgroup_sock_addr_helpers.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=27 dst=r0 src=r0 offset=0 imm=2
#line 191 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 191 "sample/cgroup_sock_addr_helpers.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[1].address);
    // EBPF_OP_MOV64_IMM pc=28 dst=r1 src=r0 offset=0 imm=3
#line 191 "sample/cgroup_sock_addr_helpers.c"
    r1 = IMMEDIATE(3);
    // EBPF_OP_STXW pc=29 dst=r10 src=r1 offset=-44 imm=0
#line 193 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-44));
    // EBPF_OP_MOV64_IMM pc=30 dst=r6 src=r0 offset=0 imm=1
#line 193 "sample/cgroup_sock_addr_helpers.c"
    r6 = IMMEDIATE(1);
    // EBPF_OP_STXDW pc=31 dst=r10 src=r6 offset=-56 imm=0
#line 194 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r6, OFFSET(-56));
    // EBPF_OP_MOV64_REG pc=32 dst=r2 src=r10 offset=0 imm=0
#line 194 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=33 dst=r2 src=r0 offset=0 imm=-44
#line 191 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-44);
    // EBPF_OP_LDDW pc=34 dst=r1 src=r1 offset=0 imm=2
#line 195 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=36 dst=r0 src=r0 offset=0 imm=1
#line 195 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_JEQ_IMM pc=37 dst=r0 src=r0 offset=3 imm=0
#line 196 "sample/cgroup_sock_addr_helpers.c"
    if (r0 == IMMEDIATE(0)) {
#line 196 "sample/cgroup_sock_addr_helpers.c"
        goto label_1;
#line 196 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_LDXDW pc=38 dst=r1 src=r0 offset=0 imm=0
#line 197 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_64(r1, r0, OFFSET(0));
    // EBPF_OP_ADD64_IMM pc=39 dst=r1 src=r0 offset=0 imm=1
#line 197 "sample/cgroup_sock_addr_helpers.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXDW pc=40 dst=r10 src=r1 offset=-56 imm=0
#line 197 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-56));
label_1:
    // EBPF_OP_MOV64_REG pc=41 dst=r2 src=r10 offset=0 imm=0
#line 197 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=42 dst=r2 src=r0 offset=0 imm=-44
#line 199 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-44);
    // EBPF_OP_MOV64_REG pc=43 dst=r3 src=r10 offset=0 imm=0
#line 199 "sample/cgroup_sock_addr_helpers.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=44 dst=r3 src=r0 offset=0 imm=-56
#line 199 "sample/cgroup_sock_addr_helpers.c"
    r3 += IMMEDIATE(-56);
    // EBPF_OP_LDDW pc=45 dst=r1 src=r1 offset=0 imm=2
#line 199 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_MOV64_IMM pc=47 dst=r4 src=r0 offset=0 imm=0
#line 199 "sample/cgroup_sock_addr_helpers.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=48 dst=r0 src=r0 offset=0 imm=2
#line 199 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
label_2:
    // EBPF_OP_MOV64_REG pc=49 dst=r0 src=r6 offset=0 imm=0
#line 202 "sample/cgroup_sock_addr_helpers.c"
    r0 = r6;
    // EBPF_OP_EXIT pc=50 dst=r0 src=r0 offset=0 imm=0
#line 202 "sample/cgroup_sock_addr_helpers.c"
    return r0;
#line 175 "sample/cgroup_sock_addr_helpers.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t test_sock_addr_helpers_v4_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     65538,
     "helper_id_65538",
    },
    {
     {1, 40, 40}, // Version header.
     2,
     "helper_id_2",
    },
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
};

static GUID test_sock_addr_helpers_v4_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID test_sock_addr_helpers_v4_attach_type_guid = {
    0x6076c13a, 0xf04f, 0x4ff8, {0x83, 0x80, 0x90, 0x85, 0x53, 0xf2, 0x22, 0x76}};
static uint16_t test_sock_addr_helpers_v4_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "cgroup~4")
static uint64_t
test_sock_addr_helpers_v4(void* context, const program_runtime_context_t* runtime_context)
#line 53 "sample/cgroup_sock_addr_helpers.c"
{
#line 53 "sample/cgroup_sock_addr_helpers.c"
    // Prologue.
#line 53 "sample/cgroup_sock_addr_helpers.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 53 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r0 = 0;
#line 53 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r1 = 0;
#line 53 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r2 = 0;
#line 53 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r3 = 0;
#line 53 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r4 = 0;
#line 53 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r5 = 0;
#line 53 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r6 = 0;
#line 53 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r10 = 0;

#line 53 "sample/cgroup_sock_addr_helpers.c"
    r1 = (uintptr_t)context;
#line 53 "sample/cgroup_sock_addr_helpers.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r6 src=r0 offset=0 imm=1
#line 53 "sample/cgroup_sock_addr_helpers.c"
    r6 = IMMEDIATE(1);
    // EBPF_OP_LDXW pc=1 dst=r2 src=r1 offset=44 imm=0
#line 58 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_32(r2, r1, OFFSET(44));
    // EBPF_OP_JNE_IMM pc=2 dst=r2 src=r0 offset=45 imm=6
#line 58 "sample/cgroup_sock_addr_helpers.c"
    if (r2 != IMMEDIATE(6)) {
#line 58 "sample/cgroup_sock_addr_helpers.c"
        goto label_2;
#line 58 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_LDXH pc=3 dst=r2 src=r1 offset=40 imm=0
#line 63 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_16(r2, r1, OFFSET(40));
    // EBPF_OP_LSH64_IMM pc=4 dst=r2 src=r0 offset=0 imm=16
#line 63 "sample/cgroup_sock_addr_helpers.c"
    r2 <<= (IMMEDIATE(16) & 63);
    // EBPF_OP_LDXW pc=5 dst=r3 src=r1 offset=24 imm=0
#line 63 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_32(r3, r1, OFFSET(24));
    // EBPF_OP_XOR64_REG pc=6 dst=r2 src=r3 offset=0 imm=0
#line 63 "sample/cgroup_sock_addr_helpers.c"
    r2 ^= r3;
    // EBPF_OP_STXW pc=7 dst=r10 src=r2 offset=-4 imm=0
#line 63 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r2, OFFSET(-4));
    // EBPF_OP_MOV64_IMM pc=8 dst=r6 src=r0 offset=0 imm=0
#line 63 "sample/cgroup_sock_addr_helpers.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=9 dst=r10 src=r6 offset=-40 imm=0
#line 66 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r6, OFFSET(-40));
    // EBPF_OP_STXDW pc=10 dst=r10 src=r6 offset=-32 imm=0
#line 66 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r6, OFFSET(-32));
    // EBPF_OP_STXDW pc=11 dst=r10 src=r6 offset=-24 imm=0
#line 66 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r6, OFFSET(-24));
    // EBPF_OP_STXDW pc=12 dst=r10 src=r6 offset=-16 imm=0
#line 66 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r6, OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=13 dst=r2 src=r10 offset=0 imm=0
#line 66 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=14 dst=r2 src=r0 offset=0 imm=-40
#line 63 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-40);
    // EBPF_OP_MOV64_IMM pc=15 dst=r3 src=r0 offset=0 imm=32
#line 67 "sample/cgroup_sock_addr_helpers.c"
    r3 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=16 dst=r0 src=r0 offset=0 imm=65538
#line 67 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LSH64_IMM pc=17 dst=r0 src=r0 offset=0 imm=32
#line 67 "sample/cgroup_sock_addr_helpers.c"
    r0 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=18 dst=r0 src=r0 offset=0 imm=32
#line 67 "sample/cgroup_sock_addr_helpers.c"
    r0 = (int64_t)r0 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_REG pc=19 dst=r6 src=r0 offset=28 imm=0
#line 67 "sample/cgroup_sock_addr_helpers.c"
    if ((int64_t)r6 > (int64_t)r0) {
#line 67 "sample/cgroup_sock_addr_helpers.c"
        goto label_2;
#line 67 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_MOV64_REG pc=20 dst=r2 src=r10 offset=0 imm=0
#line 67 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=21 dst=r2 src=r0 offset=0 imm=-4
#line 74 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=22 dst=r3 src=r10 offset=0 imm=0
#line 74 "sample/cgroup_sock_addr_helpers.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r3 src=r0 offset=0 imm=-40
#line 74 "sample/cgroup_sock_addr_helpers.c"
    r3 += IMMEDIATE(-40);
    // EBPF_OP_LDDW pc=24 dst=r1 src=r1 offset=0 imm=1
#line 74 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=26 dst=r4 src=r0 offset=0 imm=0
#line 74 "sample/cgroup_sock_addr_helpers.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=27 dst=r0 src=r0 offset=0 imm=2
#line 74 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 74 "sample/cgroup_sock_addr_helpers.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[1].address);
    // EBPF_OP_MOV64_IMM pc=28 dst=r6 src=r0 offset=0 imm=1
#line 74 "sample/cgroup_sock_addr_helpers.c"
    r6 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=29 dst=r10 src=r6 offset=-44 imm=0
#line 77 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-44));
    // EBPF_OP_STXDW pc=30 dst=r10 src=r6 offset=-56 imm=0
#line 78 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r6, OFFSET(-56));
    // EBPF_OP_MOV64_REG pc=31 dst=r2 src=r10 offset=0 imm=0
#line 78 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=32 dst=r2 src=r0 offset=0 imm=-44
#line 74 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-44);
    // EBPF_OP_LDDW pc=33 dst=r1 src=r1 offset=0 imm=2
#line 79 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=35 dst=r0 src=r0 offset=0 imm=1
#line 79 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_JEQ_IMM pc=36 dst=r0 src=r0 offset=3 imm=0
#line 80 "sample/cgroup_sock_addr_helpers.c"
    if (r0 == IMMEDIATE(0)) {
#line 80 "sample/cgroup_sock_addr_helpers.c"
        goto label_1;
#line 80 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_LDXDW pc=37 dst=r1 src=r0 offset=0 imm=0
#line 81 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_64(r1, r0, OFFSET(0));
    // EBPF_OP_ADD64_IMM pc=38 dst=r1 src=r0 offset=0 imm=1
#line 81 "sample/cgroup_sock_addr_helpers.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXDW pc=39 dst=r10 src=r1 offset=-56 imm=0
#line 81 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-56));
label_1:
    // EBPF_OP_MOV64_REG pc=40 dst=r2 src=r10 offset=0 imm=0
#line 81 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=41 dst=r2 src=r0 offset=0 imm=-44
#line 83 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-44);
    // EBPF_OP_MOV64_REG pc=42 dst=r3 src=r10 offset=0 imm=0
#line 83 "sample/cgroup_sock_addr_helpers.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=43 dst=r3 src=r0 offset=0 imm=-56
#line 83 "sample/cgroup_sock_addr_helpers.c"
    r3 += IMMEDIATE(-56);
    // EBPF_OP_LDDW pc=44 dst=r1 src=r1 offset=0 imm=2
#line 83 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_MOV64_IMM pc=46 dst=r4 src=r0 offset=0 imm=0
#line 83 "sample/cgroup_sock_addr_helpers.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=47 dst=r0 src=r0 offset=0 imm=2
#line 83 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
label_2:
    // EBPF_OP_MOV64_REG pc=48 dst=r0 src=r6 offset=0 imm=0
#line 86 "sample/cgroup_sock_addr_helpers.c"
    r0 = r6;
    // EBPF_OP_EXIT pc=49 dst=r0 src=r0 offset=0 imm=0
#line 86 "sample/cgroup_sock_addr_helpers.c"
    return r0;
#line 53 "sample/cgroup_sock_addr_helpers.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static helper_function_entry_t test_sock_addr_helpers_v6_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     65538,
     "helper_id_65538",
    },
    {
     {1, 40, 40}, // Version header.
     2,
     "helper_id_2",
    },
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
};

static GUID test_sock_addr_helpers_v6_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID test_sock_addr_helpers_v6_attach_type_guid = {
    0x54b0b6ed, 0x432a, 0x4674, {0x8b, 0x27, 0x8d, 0x9f, 0x5b, 0x40, 0xc6, 0x75}};
static uint16_t test_sock_addr_helpers_v6_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "cgroup~2")
static uint64_t
test_sock_addr_helpers_v6(void* context, const program_runtime_context_t* runtime_context)
#line 94 "sample/cgroup_sock_addr_helpers.c"
{
#line 94 "sample/cgroup_sock_addr_helpers.c"
    // Prologue.
#line 94 "sample/cgroup_sock_addr_helpers.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 94 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r0 = 0;
#line 94 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r1 = 0;
#line 94 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r2 = 0;
#line 94 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r3 = 0;
#line 94 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r4 = 0;
#line 94 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r5 = 0;
#line 94 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r6 = 0;
#line 94 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r10 = 0;

#line 94 "sample/cgroup_sock_addr_helpers.c"
    r1 = (uintptr_t)context;
#line 94 "sample/cgroup_sock_addr_helpers.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r6 src=r0 offset=0 imm=1
#line 94 "sample/cgroup_sock_addr_helpers.c"
    r6 = IMMEDIATE(1);
    // EBPF_OP_LDXW pc=1 dst=r2 src=r1 offset=44 imm=0
#line 99 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_32(r2, r1, OFFSET(44));
    // EBPF_OP_JNE_IMM pc=2 dst=r2 src=r0 offset=48 imm=6
#line 99 "sample/cgroup_sock_addr_helpers.c"
    if (r2 != IMMEDIATE(6)) {
#line 99 "sample/cgroup_sock_addr_helpers.c"
        goto label_2;
#line 99 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_LDXW pc=3 dst=r2 src=r1 offset=24 imm=0
#line 104 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_32(r2, r1, OFFSET(24));
    // EBPF_OP_LDXW pc=4 dst=r3 src=r1 offset=36 imm=0
#line 104 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_32(r3, r1, OFFSET(36));
    // EBPF_OP_XOR64_REG pc=5 dst=r3 src=r2 offset=0 imm=0
#line 104 "sample/cgroup_sock_addr_helpers.c"
    r3 ^= r2;
    // EBPF_OP_LDXH pc=6 dst=r2 src=r1 offset=40 imm=0
#line 104 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_16(r2, r1, OFFSET(40));
    // EBPF_OP_LSH64_IMM pc=7 dst=r2 src=r0 offset=0 imm=16
#line 104 "sample/cgroup_sock_addr_helpers.c"
    r2 <<= (IMMEDIATE(16) & 63);
    // EBPF_OP_XOR64_REG pc=8 dst=r3 src=r2 offset=0 imm=0
#line 104 "sample/cgroup_sock_addr_helpers.c"
    r3 ^= r2;
    // EBPF_OP_STXW pc=9 dst=r10 src=r3 offset=-4 imm=0
#line 104 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r3, OFFSET(-4));
    // EBPF_OP_MOV64_IMM pc=10 dst=r6 src=r0 offset=0 imm=0
#line 104 "sample/cgroup_sock_addr_helpers.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=11 dst=r10 src=r6 offset=-40 imm=0
#line 107 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r6, OFFSET(-40));
    // EBPF_OP_STXDW pc=12 dst=r10 src=r6 offset=-32 imm=0
#line 107 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r6, OFFSET(-32));
    // EBPF_OP_STXDW pc=13 dst=r10 src=r6 offset=-24 imm=0
#line 107 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r6, OFFSET(-24));
    // EBPF_OP_STXDW pc=14 dst=r10 src=r6 offset=-16 imm=0
#line 107 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r6, OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=15 dst=r2 src=r10 offset=0 imm=0
#line 107 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=16 dst=r2 src=r0 offset=0 imm=-40
#line 104 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-40);
    // EBPF_OP_MOV64_IMM pc=17 dst=r3 src=r0 offset=0 imm=32
#line 108 "sample/cgroup_sock_addr_helpers.c"
    r3 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=18 dst=r0 src=r0 offset=0 imm=65538
#line 108 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_LSH64_IMM pc=19 dst=r0 src=r0 offset=0 imm=32
#line 108 "sample/cgroup_sock_addr_helpers.c"
    r0 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=20 dst=r0 src=r0 offset=0 imm=32
#line 108 "sample/cgroup_sock_addr_helpers.c"
    r0 = (int64_t)r0 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_REG pc=21 dst=r6 src=r0 offset=29 imm=0
#line 108 "sample/cgroup_sock_addr_helpers.c"
    if ((int64_t)r6 > (int64_t)r0) {
#line 108 "sample/cgroup_sock_addr_helpers.c"
        goto label_2;
#line 108 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_MOV64_REG pc=22 dst=r2 src=r10 offset=0 imm=0
#line 108 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=23 dst=r2 src=r0 offset=0 imm=-4
#line 114 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=24 dst=r3 src=r10 offset=0 imm=0
#line 114 "sample/cgroup_sock_addr_helpers.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=25 dst=r3 src=r0 offset=0 imm=-40
#line 114 "sample/cgroup_sock_addr_helpers.c"
    r3 += IMMEDIATE(-40);
    // EBPF_OP_LDDW pc=26 dst=r1 src=r1 offset=0 imm=1
#line 114 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=28 dst=r4 src=r0 offset=0 imm=0
#line 114 "sample/cgroup_sock_addr_helpers.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=29 dst=r0 src=r0 offset=0 imm=2
#line 114 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 114 "sample/cgroup_sock_addr_helpers.c"
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, runtime_context->map_data[1].address);
    // EBPF_OP_MOV64_IMM pc=30 dst=r1 src=r0 offset=0 imm=2
#line 114 "sample/cgroup_sock_addr_helpers.c"
    r1 = IMMEDIATE(2);
    // EBPF_OP_STXW pc=31 dst=r10 src=r1 offset=-44 imm=0
#line 117 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-44));
    // EBPF_OP_MOV64_IMM pc=32 dst=r6 src=r0 offset=0 imm=1
#line 117 "sample/cgroup_sock_addr_helpers.c"
    r6 = IMMEDIATE(1);
    // EBPF_OP_STXDW pc=33 dst=r10 src=r6 offset=-56 imm=0
#line 118 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r6, OFFSET(-56));
    // EBPF_OP_MOV64_REG pc=34 dst=r2 src=r10 offset=0 imm=0
#line 118 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=35 dst=r2 src=r0 offset=0 imm=-44
#line 114 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-44);
    // EBPF_OP_LDDW pc=36 dst=r1 src=r1 offset=0 imm=2
#line 119 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=38 dst=r0 src=r0 offset=0 imm=1
#line 119 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
    // EBPF_OP_JEQ_IMM pc=39 dst=r0 src=r0 offset=3 imm=0
#line 120 "sample/cgroup_sock_addr_helpers.c"
    if (r0 == IMMEDIATE(0)) {
#line 120 "sample/cgroup_sock_addr_helpers.c"
        goto label_1;
#line 120 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_LDXDW pc=40 dst=r1 src=r0 offset=0 imm=0
#line 121 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_64(r1, r0, OFFSET(0));
    // EBPF_OP_ADD64_IMM pc=41 dst=r1 src=r0 offset=0 imm=1
#line 121 "sample/cgroup_sock_addr_helpers.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXDW pc=42 dst=r10 src=r1 offset=-56 imm=0
#line 121 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-56));
label_1:
    // EBPF_OP_MOV64_REG pc=43 dst=r2 src=r10 offset=0 imm=0
#line 121 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=44 dst=r2 src=r0 offset=0 imm=-44
#line 123 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-44);
    // EBPF_OP_MOV64_REG pc=45 dst=r3 src=r10 offset=0 imm=0
#line 123 "sample/cgroup_sock_addr_helpers.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=46 dst=r3 src=r0 offset=0 imm=-56
#line 123 "sample/cgroup_sock_addr_helpers.c"
    r3 += IMMEDIATE(-56);
    // EBPF_OP_LDDW pc=47 dst=r1 src=r1 offset=0 imm=2
#line 123 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_MOV64_IMM pc=49 dst=r4 src=r0 offset=0 imm=0
#line 123 "sample/cgroup_sock_addr_helpers.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=50 dst=r0 src=r0 offset=0 imm=2
#line 123 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
label_2:
    // EBPF_OP_MOV64_REG pc=51 dst=r0 src=r6 offset=0 imm=0
#line 126 "sample/cgroup_sock_addr_helpers.c"
    r0 = r6;
    // EBPF_OP_EXIT pc=52 dst=r0 src=r0 offset=0 imm=0
#line 126 "sample/cgroup_sock_addr_helpers.c"
    return r0;
#line 94 "sample/cgroup_sock_addr_helpers.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        {1, 144, 144}, // Version header.
        conditional_authorization_v4,
        "cgroup~3",
        "cgroup/connect_authorization4",
        "conditional_authorization_v4",
        conditional_authorization_v4_maps,
        1,
        conditional_authorization_v4_helpers,
        3,
        42,
        &conditional_authorization_v4_program_type_guid,
        &conditional_authorization_v4_attach_type_guid,
    },
    {
        0,
        {1, 144, 144}, // Version header.
        test_recv_accept_helpers_v4,
        "cgroup~1",
        "cgroup/recv_accept4",
        "test_recv_accept_helpers_v4",
        test_recv_accept_helpers_v4_maps,
        2,
        test_recv_accept_helpers_v4_helpers,
        3,
        51,
        &test_recv_accept_helpers_v4_program_type_guid,
        &test_recv_accept_helpers_v4_attach_type_guid,
    },
    {
        0,
        {1, 144, 144}, // Version header.
        test_sock_addr_helpers_v4,
        "cgroup~4",
        "cgroup/connect_authorization4",
        "test_sock_addr_helpers_v4",
        test_sock_addr_helpers_v4_maps,
        2,
        test_sock_addr_helpers_v4_helpers,
        3,
        50,
        &test_sock_addr_helpers_v4_program_type_guid,
        &test_sock_addr_helpers_v4_attach_type_guid,
    },
    {
        0,
        {1, 144, 144}, // Version header.
        test_sock_addr_helpers_v6,
        "cgroup~2",
        "cgroup/connect_authorization6",
        "test_sock_addr_helpers_v6",
        test_sock_addr_helpers_v6_maps,
        2,
        test_sock_addr_helpers_v6_helpers,
        3,
        53,
        &test_sock_addr_helpers_v6_program_type_guid,
        &test_sock_addr_helpers_v6_attach_type_guid,
    },
};
#pragma data_seg(pop)

static void
_get_programs(_Outptr_result_buffer_(*count) program_entry_t** programs, _Out_ size_t* count)
{
    *programs = _programs;
    *count = 4;
}

static void
_get_version(_Out_ bpf2c_version_t* version)
{
    version->major = 1;
    version->minor = 3;
    version->revision = 0;
}

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = NULL;
    *count = 0;
}

metadata_table_t cgroup_sock_addr_helpers_metadata_table = {
    sizeof(metadata_table_t),
    _get_programs,
    _get_maps,
    _get_hash,
    _get_version,
    _get_map_initial_values,
    _get_global_variable_sections,
};
