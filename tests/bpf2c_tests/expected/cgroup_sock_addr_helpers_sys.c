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
    {{0, 0},
     {
         1,  // Current Version.
         80, // Struct size up to the last field.
         80, // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_HASH, // Type of map.
         4,                 // Size in bytes of a map key.
         4,                 // Size in bytes of a map value.
         100,               // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         LIBBPF_PIN_NONE,   // Pinning type for the map.
         10,                // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "interface_type_map"},
    {{0, 0},
     {
         1,  // Current Version.
         80, // Struct size up to the last field.
         80, // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_HASH, // Type of map.
         4,                 // Size in bytes of a map key.
         4,                 // Size in bytes of a map value.
         100,               // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         LIBBPF_PIN_NONE,   // Pinning type for the map.
         12,                // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "tunnel_type_map"},
    {{0, 0},
     {
         1,  // Current Version.
         80, // Struct size up to the last field.
         80, // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_HASH, // Type of map.
         4,                 // Size in bytes of a map key.
         8,                 // Size in bytes of a map value.
         100,               // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         LIBBPF_PIN_NONE,   // Pinning type for the map.
         17,                // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "next_hop_interface_map"},
    {{0, 0},
     {
         1,  // Current Version.
         80, // Struct size up to the last field.
         80, // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_HASH, // Type of map.
         4,                 // Size in bytes of a map key.
         4,                 // Size in bytes of a map value.
         100,               // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         LIBBPF_PIN_NONE,   // Pinning type for the map.
         19,                // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "sub_interface_map"},
    {{0, 0},
     {
         1,  // Current Version.
         80, // Struct size up to the last field.
         80, // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_HASH, // Type of map.
         4,                 // Size in bytes of a map key.
         24,                // Size in bytes of a map value.
         1000,              // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         LIBBPF_PIN_NONE,   // Pinning type for the map.
         26,                // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "test_results_map"},
    {{0, 0},
     {
         1,  // Current Version.
         80, // Struct size up to the last field.
         80, // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_HASH, // Type of map.
         4,                 // Size in bytes of a map key.
         8,                 // Size in bytes of a map value.
         1,                 // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         LIBBPF_PIN_NONE,   // Pinning type for the map.
         28,                // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "connection_count_map"},
};
#pragma data_seg(pop)

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = _maps;
    *count = 6;
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
        65539,
        "helper_id_65539",
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
    {
        {1, 40, 40}, // Version header.
        65540,
        "helper_id_65540",
    },
    {
        {1, 40, 40}, // Version header.
        65541,
        "helper_id_65541",
    },
};

static GUID conditional_authorization_v4_program_type_guid = {
    0x92ec8e39, 0xaeec, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};
static GUID conditional_authorization_v4_attach_type_guid = {
    0x6076c13a, 0xf04f, 0x4ff8, {0x83, 0x80, 0x90, 0x85, 0x53, 0xf2, 0x22, 0x76}};
static uint16_t conditional_authorization_v4_maps[] = {
    5,
};

#pragma code_seg(push, "cgroup~2")
static uint64_t
conditional_authorization_v4(void* context, const program_runtime_context_t* runtime_context)
#line 104 "sample/cgroup_sock_addr_helpers.c"
{
#line 104 "sample/cgroup_sock_addr_helpers.c"
    // Prologue.
#line 104 "sample/cgroup_sock_addr_helpers.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 104 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r0 = 0;
#line 104 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r1 = 0;
#line 104 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r2 = 0;
#line 104 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r3 = 0;
#line 104 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r4 = 0;
#line 104 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r5 = 0;
#line 104 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r6 = 0;
#line 104 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r7 = 0;
#line 104 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r10 = 0;

#line 104 "sample/cgroup_sock_addr_helpers.c"
    r1 = (uintptr_t)context;
#line 104 "sample/cgroup_sock_addr_helpers.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 104 "sample/cgroup_sock_addr_helpers.c"
    r6 = r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r0 src=r0 offset=0 imm=1
#line 104 "sample/cgroup_sock_addr_helpers.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_LDXW pc=2 dst=r1 src=r6 offset=44 imm=0
#line 109 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_32(r1, r6, OFFSET(44));
    // EBPF_OP_JNE_IMM pc=3 dst=r1 src=r0 offset=39 imm=6
#line 109 "sample/cgroup_sock_addr_helpers.c"
    if (r1 != IMMEDIATE(6)) {
#line 109 "sample/cgroup_sock_addr_helpers.c"
        goto label_3;
#line 109 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_MOV64_REG pc=4 dst=r1 src=r6 offset=0 imm=0
#line 109 "sample/cgroup_sock_addr_helpers.c"
    r1 = r6;
    // EBPF_OP_CALL pc=5 dst=r0 src=r0 offset=0 imm=65538
#line 109 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 109 "sample/cgroup_sock_addr_helpers.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 109 "sample/cgroup_sock_addr_helpers.c"
        return 0;
#line 109 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_MOV64_REG pc=6 dst=r7 src=r0 offset=0 imm=0
#line 109 "sample/cgroup_sock_addr_helpers.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=7 dst=r1 src=r6 offset=0 imm=0
#line 109 "sample/cgroup_sock_addr_helpers.c"
    r1 = r6;
    // EBPF_OP_CALL pc=8 dst=r0 src=r0 offset=0 imm=65539
#line 112 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 112 "sample/cgroup_sock_addr_helpers.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 112 "sample/cgroup_sock_addr_helpers.c"
        return 0;
#line 112 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_MOV64_REG pc=9 dst=r1 src=r0 offset=0 imm=0
#line 112 "sample/cgroup_sock_addr_helpers.c"
    r1 = r0;
    // EBPF_OP_MOV64_IMM pc=10 dst=r0 src=r0 offset=0 imm=0
#line 113 "sample/cgroup_sock_addr_helpers.c"
    r0 = IMMEDIATE(0);
    // EBPF_OP_LSH64_IMM pc=11 dst=r7 src=r0 offset=0 imm=32
#line 113 "sample/cgroup_sock_addr_helpers.c"
    r7 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_RSH64_IMM pc=12 dst=r7 src=r0 offset=0 imm=32
#line 113 "sample/cgroup_sock_addr_helpers.c"
    r7 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=13 dst=r7 src=r0 offset=29 imm=23
#line 114 "sample/cgroup_sock_addr_helpers.c"
    if (r7 == IMMEDIATE(23)) {
#line 114 "sample/cgroup_sock_addr_helpers.c"
        goto label_3;
#line 114 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_LSH64_IMM pc=14 dst=r1 src=r0 offset=0 imm=32
#line 114 "sample/cgroup_sock_addr_helpers.c"
    r1 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_RSH64_IMM pc=15 dst=r1 src=r0 offset=0 imm=32
#line 114 "sample/cgroup_sock_addr_helpers.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=16 dst=r1 src=r0 offset=21 imm=0
#line 115 "sample/cgroup_sock_addr_helpers.c"
    if (r1 == IMMEDIATE(0)) {
#line 115 "sample/cgroup_sock_addr_helpers.c"
        goto label_2;
#line 115 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_MOV64_IMM pc=17 dst=r1 src=r0 offset=0 imm=100
#line 115 "sample/cgroup_sock_addr_helpers.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXW pc=18 dst=r10 src=r1 offset=-4 imm=0
#line 115 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
    // EBPF_OP_MOV64_IMM pc=19 dst=r1 src=r0 offset=0 imm=1
#line 115 "sample/cgroup_sock_addr_helpers.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXDW pc=20 dst=r10 src=r1 offset=-16 imm=0
#line 109 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
    // EBPF_OP_MOV64_REG pc=21 dst=r2 src=r10 offset=0 imm=0
#line 109 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=22 dst=r2 src=r0 offset=0 imm=-4
#line 109 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=23 dst=r1 src=r1 offset=0 imm=6
#line 118 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[5].address);
    // EBPF_OP_CALL pc=25 dst=r0 src=r0 offset=0 imm=1
#line 118 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 118 "sample/cgroup_sock_addr_helpers.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 118 "sample/cgroup_sock_addr_helpers.c"
        return 0;
#line 118 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_JEQ_IMM pc=26 dst=r0 src=r0 offset=3 imm=0
#line 118 "sample/cgroup_sock_addr_helpers.c"
    if (r0 == IMMEDIATE(0)) {
#line 118 "sample/cgroup_sock_addr_helpers.c"
        goto label_1;
#line 118 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_LDXDW pc=27 dst=r1 src=r0 offset=0 imm=0
#line 118 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_64(r1, r0, OFFSET(0));
    // EBPF_OP_ADD64_IMM pc=28 dst=r1 src=r0 offset=0 imm=1
#line 118 "sample/cgroup_sock_addr_helpers.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXDW pc=29 dst=r10 src=r1 offset=-16 imm=0
#line 109 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-16));
label_1:
    // EBPF_OP_MOV64_REG pc=30 dst=r2 src=r10 offset=0 imm=0
#line 119 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=31 dst=r2 src=r0 offset=0 imm=-4
#line 119 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=32 dst=r3 src=r10 offset=0 imm=0
#line 119 "sample/cgroup_sock_addr_helpers.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=33 dst=r3 src=r0 offset=0 imm=-16
#line 119 "sample/cgroup_sock_addr_helpers.c"
    r3 += IMMEDIATE(-16);
    // EBPF_OP_LDDW pc=34 dst=r1 src=r1 offset=0 imm=6
#line 119 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[5].address);
    // EBPF_OP_MOV64_IMM pc=36 dst=r4 src=r0 offset=0 imm=0
#line 109 "sample/cgroup_sock_addr_helpers.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=37 dst=r0 src=r0 offset=0 imm=2
#line 120 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
#line 120 "sample/cgroup_sock_addr_helpers.c"
    if ((runtime_context->helper_data[3].tail_call) && (r0 == 0)) {
#line 120 "sample/cgroup_sock_addr_helpers.c"
        return 0;
#line 120 "sample/cgroup_sock_addr_helpers.c"
    }
label_2:
    // EBPF_OP_MOV64_REG pc=38 dst=r1 src=r6 offset=0 imm=0
#line 120 "sample/cgroup_sock_addr_helpers.c"
    r1 = r6;
    // EBPF_OP_CALL pc=39 dst=r0 src=r0 offset=0 imm=65540
#line 120 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 120 "sample/cgroup_sock_addr_helpers.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 120 "sample/cgroup_sock_addr_helpers.c"
        return 0;
#line 120 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_MOV64_REG pc=40 dst=r1 src=r6 offset=0 imm=0
#line 120 "sample/cgroup_sock_addr_helpers.c"
    r1 = r6;
    // EBPF_OP_CALL pc=41 dst=r0 src=r0 offset=0 imm=65541
#line 120 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[5].address(r1, r2, r3, r4, r5, context);
#line 120 "sample/cgroup_sock_addr_helpers.c"
    if ((runtime_context->helper_data[5].tail_call) && (r0 == 0)) {
#line 120 "sample/cgroup_sock_addr_helpers.c"
        return 0;
#line 120 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_MOV64_IMM pc=42 dst=r0 src=r0 offset=0 imm=1
#line 120 "sample/cgroup_sock_addr_helpers.c"
    r0 = IMMEDIATE(1);
label_3:
    // EBPF_OP_EXIT pc=43 dst=r0 src=r0 offset=0 imm=0
#line 109 "sample/cgroup_sock_addr_helpers.c"
    return r0;
#line 104 "sample/cgroup_sock_addr_helpers.c"
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
        65539,
        "helper_id_65539",
    },
    {
        {1, 40, 40}, // Version header.
        65540,
        "helper_id_65540",
    },
    {
        {1, 40, 40}, // Version header.
        65541,
        "helper_id_65541",
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
    2,
    3,
    4,
    5,
};

#pragma code_seg(push, "cgroup~3")
static uint64_t
test_sock_addr_helpers_v4(void* context, const program_runtime_context_t* runtime_context)
#line 104 "sample/cgroup_sock_addr_helpers.c"
{
#line 104 "sample/cgroup_sock_addr_helpers.c"
    // Prologue.
#line 104 "sample/cgroup_sock_addr_helpers.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 104 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r0 = 0;
#line 104 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r1 = 0;
#line 104 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r2 = 0;
#line 104 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r3 = 0;
#line 104 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r4 = 0;
#line 104 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r5 = 0;
#line 104 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r6 = 0;
#line 104 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r10 = 0;

#line 104 "sample/cgroup_sock_addr_helpers.c"
    r1 = (uintptr_t)context;
#line 104 "sample/cgroup_sock_addr_helpers.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_LDXW pc=0 dst=r2 src=r1 offset=44 imm=0
#line 104 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_32(r2, r1, OFFSET(44));
    // EBPF_OP_JNE_IMM pc=1 dst=r2 src=r0 offset=84 imm=6
#line 104 "sample/cgroup_sock_addr_helpers.c"
    if (r2 != IMMEDIATE(6)) {
#line 104 "sample/cgroup_sock_addr_helpers.c"
        goto label_2;
#line 104 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_LDXH pc=2 dst=r2 src=r1 offset=40 imm=0
#line 109 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_16(r2, r1, OFFSET(40));
    // EBPF_OP_LSH64_IMM pc=3 dst=r2 src=r0 offset=0 imm=16
#line 109 "sample/cgroup_sock_addr_helpers.c"
    r2 <<= (IMMEDIATE(16) & 63);
    // EBPF_OP_LDXW pc=4 dst=r3 src=r1 offset=24 imm=0
#line 109 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_32(r3, r1, OFFSET(24));
    // EBPF_OP_XOR64_REG pc=5 dst=r2 src=r3 offset=0 imm=0
#line 109 "sample/cgroup_sock_addr_helpers.c"
    r2 ^= r3;
    // EBPF_OP_STXW pc=6 dst=r10 src=r2 offset=-4 imm=0
#line 109 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r2, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=7 dst=r6 src=r1 offset=0 imm=0
#line 109 "sample/cgroup_sock_addr_helpers.c"
    r6 = r1;
    // EBPF_OP_CALL pc=8 dst=r0 src=r0 offset=0 imm=65538
#line 112 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 112 "sample/cgroup_sock_addr_helpers.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 112 "sample/cgroup_sock_addr_helpers.c"
        return 0;
#line 112 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_STXW pc=9 dst=r10 src=r0 offset=-8 imm=0
#line 112 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r0, OFFSET(-8));
    // EBPF_OP_MOV64_REG pc=10 dst=r1 src=r6 offset=0 imm=0
#line 113 "sample/cgroup_sock_addr_helpers.c"
    r1 = r6;
    // EBPF_OP_CALL pc=11 dst=r0 src=r0 offset=0 imm=65539
#line 113 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 113 "sample/cgroup_sock_addr_helpers.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 113 "sample/cgroup_sock_addr_helpers.c"
        return 0;
#line 113 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_STXW pc=12 dst=r10 src=r0 offset=-12 imm=0
#line 113 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r0, OFFSET(-12));
    // EBPF_OP_MOV64_REG pc=13 dst=r1 src=r6 offset=0 imm=0
#line 114 "sample/cgroup_sock_addr_helpers.c"
    r1 = r6;
    // EBPF_OP_CALL pc=14 dst=r0 src=r0 offset=0 imm=65540
#line 114 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 114 "sample/cgroup_sock_addr_helpers.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 114 "sample/cgroup_sock_addr_helpers.c"
        return 0;
#line 114 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_STXDW pc=15 dst=r10 src=r0 offset=-24 imm=0
#line 114 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r0, OFFSET(-24));
    // EBPF_OP_MOV64_REG pc=16 dst=r1 src=r6 offset=0 imm=0
#line 115 "sample/cgroup_sock_addr_helpers.c"
    r1 = r6;
    // EBPF_OP_CALL pc=17 dst=r0 src=r0 offset=0 imm=65541
#line 115 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
#line 115 "sample/cgroup_sock_addr_helpers.c"
    if ((runtime_context->helper_data[3].tail_call) && (r0 == 0)) {
#line 115 "sample/cgroup_sock_addr_helpers.c"
        return 0;
#line 115 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_STXW pc=18 dst=r10 src=r0 offset=-28 imm=0
#line 115 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r0, OFFSET(-28));
    // EBPF_OP_MOV64_REG pc=19 dst=r6 src=r10 offset=0 imm=0
#line 115 "sample/cgroup_sock_addr_helpers.c"
    r6 = r10;
    // EBPF_OP_ADD64_IMM pc=20 dst=r6 src=r0 offset=0 imm=-4
#line 109 "sample/cgroup_sock_addr_helpers.c"
    r6 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=21 dst=r3 src=r10 offset=0 imm=0
#line 109 "sample/cgroup_sock_addr_helpers.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=22 dst=r3 src=r0 offset=0 imm=-8
#line 109 "sample/cgroup_sock_addr_helpers.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=23 dst=r1 src=r1 offset=0 imm=1
#line 118 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_REG pc=25 dst=r2 src=r6 offset=0 imm=0
#line 118 "sample/cgroup_sock_addr_helpers.c"
    r2 = r6;
    // EBPF_OP_MOV64_IMM pc=26 dst=r4 src=r0 offset=0 imm=0
#line 118 "sample/cgroup_sock_addr_helpers.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=27 dst=r0 src=r0 offset=0 imm=2
#line 118 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 118 "sample/cgroup_sock_addr_helpers.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 118 "sample/cgroup_sock_addr_helpers.c"
        return 0;
#line 118 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_MOV64_REG pc=28 dst=r3 src=r10 offset=0 imm=0
#line 118 "sample/cgroup_sock_addr_helpers.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=29 dst=r3 src=r0 offset=0 imm=-12
#line 109 "sample/cgroup_sock_addr_helpers.c"
    r3 += IMMEDIATE(-12);
    // EBPF_OP_LDDW pc=30 dst=r1 src=r1 offset=0 imm=2
#line 119 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_MOV64_REG pc=32 dst=r2 src=r6 offset=0 imm=0
#line 119 "sample/cgroup_sock_addr_helpers.c"
    r2 = r6;
    // EBPF_OP_MOV64_IMM pc=33 dst=r4 src=r0 offset=0 imm=0
#line 119 "sample/cgroup_sock_addr_helpers.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=34 dst=r0 src=r0 offset=0 imm=2
#line 119 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 119 "sample/cgroup_sock_addr_helpers.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 119 "sample/cgroup_sock_addr_helpers.c"
        return 0;
#line 119 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_MOV64_REG pc=35 dst=r3 src=r10 offset=0 imm=0
#line 119 "sample/cgroup_sock_addr_helpers.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=36 dst=r3 src=r0 offset=0 imm=-24
#line 109 "sample/cgroup_sock_addr_helpers.c"
    r3 += IMMEDIATE(-24);
    // EBPF_OP_LDDW pc=37 dst=r1 src=r1 offset=0 imm=3
#line 120 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[2].address);
    // EBPF_OP_MOV64_REG pc=39 dst=r2 src=r6 offset=0 imm=0
#line 120 "sample/cgroup_sock_addr_helpers.c"
    r2 = r6;
    // EBPF_OP_MOV64_IMM pc=40 dst=r4 src=r0 offset=0 imm=0
#line 120 "sample/cgroup_sock_addr_helpers.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=41 dst=r0 src=r0 offset=0 imm=2
#line 120 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 120 "sample/cgroup_sock_addr_helpers.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 120 "sample/cgroup_sock_addr_helpers.c"
        return 0;
#line 120 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_MOV64_REG pc=42 dst=r3 src=r10 offset=0 imm=0
#line 120 "sample/cgroup_sock_addr_helpers.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=43 dst=r3 src=r0 offset=0 imm=-28
#line 109 "sample/cgroup_sock_addr_helpers.c"
    r3 += IMMEDIATE(-28);
    // EBPF_OP_LDDW pc=44 dst=r1 src=r1 offset=0 imm=4
#line 121 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[3].address);
    // EBPF_OP_MOV64_REG pc=46 dst=r2 src=r6 offset=0 imm=0
#line 121 "sample/cgroup_sock_addr_helpers.c"
    r2 = r6;
    // EBPF_OP_MOV64_IMM pc=47 dst=r4 src=r0 offset=0 imm=0
#line 121 "sample/cgroup_sock_addr_helpers.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=48 dst=r0 src=r0 offset=0 imm=2
#line 121 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 121 "sample/cgroup_sock_addr_helpers.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 121 "sample/cgroup_sock_addr_helpers.c"
        return 0;
#line 121 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_LDXW pc=49 dst=r1 src=r10 offset=-8 imm=0
#line 125 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_32(r1, r10, OFFSET(-8));
    // EBPF_OP_STXW pc=50 dst=r10 src=r1 offset=-56 imm=0
#line 124 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-56));
    // EBPF_OP_LDXW pc=51 dst=r1 src=r10 offset=-12 imm=0
#line 126 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_32(r1, r10, OFFSET(-12));
    // EBPF_OP_STXW pc=52 dst=r10 src=r1 offset=-52 imm=0
#line 124 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-52));
    // EBPF_OP_LDXDW pc=53 dst=r1 src=r10 offset=-24 imm=0
#line 127 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_64(r1, r10, OFFSET(-24));
    // EBPF_OP_STXDW pc=54 dst=r10 src=r1 offset=-48 imm=0
#line 124 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
    // EBPF_OP_LDXW pc=55 dst=r1 src=r10 offset=-28 imm=0
#line 128 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_32(r1, r10, OFFSET(-28));
    // EBPF_OP_STXW pc=56 dst=r10 src=r1 offset=-40 imm=0
#line 124 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-40));
    // EBPF_OP_LDXW pc=57 dst=r1 src=r10 offset=-4 imm=0
#line 129 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_32(r1, r10, OFFSET(-4));
    // EBPF_OP_STXW pc=58 dst=r10 src=r1 offset=-36 imm=0
#line 124 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-36));
    // EBPF_OP_MOV64_REG pc=59 dst=r3 src=r10 offset=0 imm=0
#line 124 "sample/cgroup_sock_addr_helpers.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=60 dst=r3 src=r0 offset=0 imm=-56
#line 109 "sample/cgroup_sock_addr_helpers.c"
    r3 += IMMEDIATE(-56);
    // EBPF_OP_LDDW pc=61 dst=r1 src=r1 offset=0 imm=5
#line 130 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[4].address);
    // EBPF_OP_MOV64_REG pc=63 dst=r2 src=r6 offset=0 imm=0
#line 130 "sample/cgroup_sock_addr_helpers.c"
    r2 = r6;
    // EBPF_OP_MOV64_IMM pc=64 dst=r4 src=r0 offset=0 imm=0
#line 130 "sample/cgroup_sock_addr_helpers.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=65 dst=r0 src=r0 offset=0 imm=2
#line 130 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 130 "sample/cgroup_sock_addr_helpers.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 130 "sample/cgroup_sock_addr_helpers.c"
        return 0;
#line 130 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_MOV64_IMM pc=66 dst=r1 src=r0 offset=0 imm=1
#line 130 "sample/cgroup_sock_addr_helpers.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=67 dst=r10 src=r1 offset=-60 imm=0
#line 133 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-60));
    // EBPF_OP_STXDW pc=68 dst=r10 src=r1 offset=-72 imm=0
#line 134 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-72));
    // EBPF_OP_MOV64_REG pc=69 dst=r2 src=r10 offset=0 imm=0
#line 134 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=70 dst=r2 src=r0 offset=0 imm=-60
#line 109 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-60);
    // EBPF_OP_LDDW pc=71 dst=r1 src=r1 offset=0 imm=6
#line 135 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[5].address);
    // EBPF_OP_CALL pc=73 dst=r0 src=r0 offset=0 imm=1
#line 135 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[5].address(r1, r2, r3, r4, r5, context);
#line 135 "sample/cgroup_sock_addr_helpers.c"
    if ((runtime_context->helper_data[5].tail_call) && (r0 == 0)) {
#line 135 "sample/cgroup_sock_addr_helpers.c"
        return 0;
#line 135 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_JEQ_IMM pc=74 dst=r0 src=r0 offset=3 imm=0
#line 136 "sample/cgroup_sock_addr_helpers.c"
    if (r0 == IMMEDIATE(0)) {
#line 136 "sample/cgroup_sock_addr_helpers.c"
        goto label_1;
#line 136 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_LDXDW pc=75 dst=r1 src=r0 offset=0 imm=0
#line 137 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_64(r1, r0, OFFSET(0));
    // EBPF_OP_ADD64_IMM pc=76 dst=r1 src=r0 offset=0 imm=1
#line 137 "sample/cgroup_sock_addr_helpers.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXDW pc=77 dst=r10 src=r1 offset=-72 imm=0
#line 137 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-72));
label_1:
    // EBPF_OP_MOV64_REG pc=78 dst=r2 src=r10 offset=0 imm=0
#line 137 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=79 dst=r2 src=r0 offset=0 imm=-60
#line 139 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-60);
    // EBPF_OP_MOV64_REG pc=80 dst=r3 src=r10 offset=0 imm=0
#line 139 "sample/cgroup_sock_addr_helpers.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=81 dst=r3 src=r0 offset=0 imm=-72
#line 139 "sample/cgroup_sock_addr_helpers.c"
    r3 += IMMEDIATE(-72);
    // EBPF_OP_LDDW pc=82 dst=r1 src=r1 offset=0 imm=6
#line 139 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[5].address);
    // EBPF_OP_MOV64_IMM pc=84 dst=r4 src=r0 offset=0 imm=0
#line 139 "sample/cgroup_sock_addr_helpers.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=85 dst=r0 src=r0 offset=0 imm=2
#line 139 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 139 "sample/cgroup_sock_addr_helpers.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 139 "sample/cgroup_sock_addr_helpers.c"
        return 0;
#line 139 "sample/cgroup_sock_addr_helpers.c"
    }
label_2:
    // EBPF_OP_MOV64_IMM pc=86 dst=r0 src=r0 offset=0 imm=1
#line 146 "sample/cgroup_sock_addr_helpers.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=87 dst=r0 src=r0 offset=0 imm=0
#line 146 "sample/cgroup_sock_addr_helpers.c"
    return r0;
#line 104 "sample/cgroup_sock_addr_helpers.c"
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
        65539,
        "helper_id_65539",
    },
    {
        {1, 40, 40}, // Version header.
        65540,
        "helper_id_65540",
    },
    {
        {1, 40, 40}, // Version header.
        65541,
        "helper_id_65541",
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
    2,
    3,
    4,
    5,
};

#pragma code_seg(push, "cgroup~1")
static uint64_t
test_sock_addr_helpers_v6(void* context, const program_runtime_context_t* runtime_context)
#line 159 "sample/cgroup_sock_addr_helpers.c"
{
#line 159 "sample/cgroup_sock_addr_helpers.c"
    // Prologue.
#line 159 "sample/cgroup_sock_addr_helpers.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 159 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r0 = 0;
#line 159 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r1 = 0;
#line 159 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r2 = 0;
#line 159 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r3 = 0;
#line 159 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r4 = 0;
#line 159 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r5 = 0;
#line 159 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r6 = 0;
#line 159 "sample/cgroup_sock_addr_helpers.c"
    register uint64_t r10 = 0;

#line 159 "sample/cgroup_sock_addr_helpers.c"
    r1 = (uintptr_t)context;
#line 159 "sample/cgroup_sock_addr_helpers.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_LDXW pc=0 dst=r2 src=r1 offset=44 imm=0
#line 159 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_32(r2, r1, OFFSET(44));
    // EBPF_OP_JNE_IMM pc=1 dst=r2 src=r0 offset=87 imm=6
#line 159 "sample/cgroup_sock_addr_helpers.c"
    if (r2 != IMMEDIATE(6)) {
#line 159 "sample/cgroup_sock_addr_helpers.c"
        goto label_2;
#line 159 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_LDXW pc=2 dst=r2 src=r1 offset=24 imm=0
#line 164 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_32(r2, r1, OFFSET(24));
    // EBPF_OP_LDXW pc=3 dst=r3 src=r1 offset=36 imm=0
#line 164 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_32(r3, r1, OFFSET(36));
    // EBPF_OP_XOR64_REG pc=4 dst=r3 src=r2 offset=0 imm=0
#line 164 "sample/cgroup_sock_addr_helpers.c"
    r3 ^= r2;
    // EBPF_OP_LDXH pc=5 dst=r2 src=r1 offset=40 imm=0
#line 164 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_16(r2, r1, OFFSET(40));
    // EBPF_OP_LSH64_IMM pc=6 dst=r2 src=r0 offset=0 imm=16
#line 164 "sample/cgroup_sock_addr_helpers.c"
    r2 <<= (IMMEDIATE(16) & 63);
    // EBPF_OP_XOR64_REG pc=7 dst=r3 src=r2 offset=0 imm=0
#line 164 "sample/cgroup_sock_addr_helpers.c"
    r3 ^= r2;
    // EBPF_OP_STXW pc=8 dst=r10 src=r3 offset=-4 imm=0
#line 164 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r3, OFFSET(-4));
    // EBPF_OP_MOV64_REG pc=9 dst=r6 src=r1 offset=0 imm=0
#line 164 "sample/cgroup_sock_addr_helpers.c"
    r6 = r1;
    // EBPF_OP_CALL pc=10 dst=r0 src=r0 offset=0 imm=65538
#line 167 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 167 "sample/cgroup_sock_addr_helpers.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 167 "sample/cgroup_sock_addr_helpers.c"
        return 0;
#line 167 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_STXW pc=11 dst=r10 src=r0 offset=-8 imm=0
#line 167 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r0, OFFSET(-8));
    // EBPF_OP_MOV64_REG pc=12 dst=r1 src=r6 offset=0 imm=0
#line 168 "sample/cgroup_sock_addr_helpers.c"
    r1 = r6;
    // EBPF_OP_CALL pc=13 dst=r0 src=r0 offset=0 imm=65539
#line 168 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 168 "sample/cgroup_sock_addr_helpers.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 168 "sample/cgroup_sock_addr_helpers.c"
        return 0;
#line 168 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_STXW pc=14 dst=r10 src=r0 offset=-12 imm=0
#line 168 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r0, OFFSET(-12));
    // EBPF_OP_MOV64_REG pc=15 dst=r1 src=r6 offset=0 imm=0
#line 169 "sample/cgroup_sock_addr_helpers.c"
    r1 = r6;
    // EBPF_OP_CALL pc=16 dst=r0 src=r0 offset=0 imm=65540
#line 169 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 169 "sample/cgroup_sock_addr_helpers.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 169 "sample/cgroup_sock_addr_helpers.c"
        return 0;
#line 169 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_STXDW pc=17 dst=r10 src=r0 offset=-24 imm=0
#line 169 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r0, OFFSET(-24));
    // EBPF_OP_MOV64_REG pc=18 dst=r1 src=r6 offset=0 imm=0
#line 170 "sample/cgroup_sock_addr_helpers.c"
    r1 = r6;
    // EBPF_OP_CALL pc=19 dst=r0 src=r0 offset=0 imm=65541
#line 170 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
#line 170 "sample/cgroup_sock_addr_helpers.c"
    if ((runtime_context->helper_data[3].tail_call) && (r0 == 0)) {
#line 170 "sample/cgroup_sock_addr_helpers.c"
        return 0;
#line 170 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_STXW pc=20 dst=r10 src=r0 offset=-28 imm=0
#line 170 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r0, OFFSET(-28));
    // EBPF_OP_MOV64_REG pc=21 dst=r6 src=r10 offset=0 imm=0
#line 170 "sample/cgroup_sock_addr_helpers.c"
    r6 = r10;
    // EBPF_OP_ADD64_IMM pc=22 dst=r6 src=r0 offset=0 imm=-4
#line 164 "sample/cgroup_sock_addr_helpers.c"
    r6 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=23 dst=r3 src=r10 offset=0 imm=0
#line 164 "sample/cgroup_sock_addr_helpers.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=24 dst=r3 src=r0 offset=0 imm=-8
#line 164 "sample/cgroup_sock_addr_helpers.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=25 dst=r1 src=r1 offset=0 imm=1
#line 173 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_REG pc=27 dst=r2 src=r6 offset=0 imm=0
#line 173 "sample/cgroup_sock_addr_helpers.c"
    r2 = r6;
    // EBPF_OP_MOV64_IMM pc=28 dst=r4 src=r0 offset=0 imm=0
#line 173 "sample/cgroup_sock_addr_helpers.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=29 dst=r0 src=r0 offset=0 imm=2
#line 173 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 173 "sample/cgroup_sock_addr_helpers.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 173 "sample/cgroup_sock_addr_helpers.c"
        return 0;
#line 173 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_MOV64_REG pc=30 dst=r3 src=r10 offset=0 imm=0
#line 173 "sample/cgroup_sock_addr_helpers.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=31 dst=r3 src=r0 offset=0 imm=-12
#line 164 "sample/cgroup_sock_addr_helpers.c"
    r3 += IMMEDIATE(-12);
    // EBPF_OP_LDDW pc=32 dst=r1 src=r1 offset=0 imm=2
#line 174 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_MOV64_REG pc=34 dst=r2 src=r6 offset=0 imm=0
#line 174 "sample/cgroup_sock_addr_helpers.c"
    r2 = r6;
    // EBPF_OP_MOV64_IMM pc=35 dst=r4 src=r0 offset=0 imm=0
#line 174 "sample/cgroup_sock_addr_helpers.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=36 dst=r0 src=r0 offset=0 imm=2
#line 174 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 174 "sample/cgroup_sock_addr_helpers.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 174 "sample/cgroup_sock_addr_helpers.c"
        return 0;
#line 174 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_MOV64_REG pc=37 dst=r3 src=r10 offset=0 imm=0
#line 174 "sample/cgroup_sock_addr_helpers.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=38 dst=r3 src=r0 offset=0 imm=-24
#line 164 "sample/cgroup_sock_addr_helpers.c"
    r3 += IMMEDIATE(-24);
    // EBPF_OP_LDDW pc=39 dst=r1 src=r1 offset=0 imm=3
#line 175 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[2].address);
    // EBPF_OP_MOV64_REG pc=41 dst=r2 src=r6 offset=0 imm=0
#line 175 "sample/cgroup_sock_addr_helpers.c"
    r2 = r6;
    // EBPF_OP_MOV64_IMM pc=42 dst=r4 src=r0 offset=0 imm=0
#line 175 "sample/cgroup_sock_addr_helpers.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=43 dst=r0 src=r0 offset=0 imm=2
#line 175 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 175 "sample/cgroup_sock_addr_helpers.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 175 "sample/cgroup_sock_addr_helpers.c"
        return 0;
#line 175 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_MOV64_REG pc=44 dst=r3 src=r10 offset=0 imm=0
#line 175 "sample/cgroup_sock_addr_helpers.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=45 dst=r3 src=r0 offset=0 imm=-28
#line 164 "sample/cgroup_sock_addr_helpers.c"
    r3 += IMMEDIATE(-28);
    // EBPF_OP_LDDW pc=46 dst=r1 src=r1 offset=0 imm=4
#line 176 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[3].address);
    // EBPF_OP_MOV64_REG pc=48 dst=r2 src=r6 offset=0 imm=0
#line 176 "sample/cgroup_sock_addr_helpers.c"
    r2 = r6;
    // EBPF_OP_MOV64_IMM pc=49 dst=r4 src=r0 offset=0 imm=0
#line 176 "sample/cgroup_sock_addr_helpers.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=50 dst=r0 src=r0 offset=0 imm=2
#line 176 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 176 "sample/cgroup_sock_addr_helpers.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 176 "sample/cgroup_sock_addr_helpers.c"
        return 0;
#line 176 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_LDXW pc=51 dst=r1 src=r10 offset=-8 imm=0
#line 180 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_32(r1, r10, OFFSET(-8));
    // EBPF_OP_STXW pc=52 dst=r10 src=r1 offset=-56 imm=0
#line 179 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-56));
    // EBPF_OP_LDXW pc=53 dst=r1 src=r10 offset=-12 imm=0
#line 181 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_32(r1, r10, OFFSET(-12));
    // EBPF_OP_STXW pc=54 dst=r10 src=r1 offset=-52 imm=0
#line 179 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-52));
    // EBPF_OP_LDXDW pc=55 dst=r1 src=r10 offset=-24 imm=0
#line 182 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_64(r1, r10, OFFSET(-24));
    // EBPF_OP_STXDW pc=56 dst=r10 src=r1 offset=-48 imm=0
#line 179 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
    // EBPF_OP_LDXW pc=57 dst=r1 src=r10 offset=-28 imm=0
#line 183 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_32(r1, r10, OFFSET(-28));
    // EBPF_OP_STXW pc=58 dst=r10 src=r1 offset=-40 imm=0
#line 179 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-40));
    // EBPF_OP_LDXW pc=59 dst=r1 src=r10 offset=-4 imm=0
#line 184 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_32(r1, r10, OFFSET(-4));
    // EBPF_OP_STXW pc=60 dst=r10 src=r1 offset=-36 imm=0
#line 179 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-36));
    // EBPF_OP_MOV64_REG pc=61 dst=r3 src=r10 offset=0 imm=0
#line 179 "sample/cgroup_sock_addr_helpers.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=62 dst=r3 src=r0 offset=0 imm=-56
#line 164 "sample/cgroup_sock_addr_helpers.c"
    r3 += IMMEDIATE(-56);
    // EBPF_OP_LDDW pc=63 dst=r1 src=r1 offset=0 imm=5
#line 185 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[4].address);
    // EBPF_OP_MOV64_REG pc=65 dst=r2 src=r6 offset=0 imm=0
#line 185 "sample/cgroup_sock_addr_helpers.c"
    r2 = r6;
    // EBPF_OP_MOV64_IMM pc=66 dst=r4 src=r0 offset=0 imm=0
#line 185 "sample/cgroup_sock_addr_helpers.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=67 dst=r0 src=r0 offset=0 imm=2
#line 185 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 185 "sample/cgroup_sock_addr_helpers.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 185 "sample/cgroup_sock_addr_helpers.c"
        return 0;
#line 185 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_MOV64_IMM pc=68 dst=r1 src=r0 offset=0 imm=2
#line 185 "sample/cgroup_sock_addr_helpers.c"
    r1 = IMMEDIATE(2);
    // EBPF_OP_STXW pc=69 dst=r10 src=r1 offset=-60 imm=0
#line 188 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-60));
    // EBPF_OP_MOV64_IMM pc=70 dst=r1 src=r0 offset=0 imm=1
#line 188 "sample/cgroup_sock_addr_helpers.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXDW pc=71 dst=r10 src=r1 offset=-72 imm=0
#line 189 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-72));
    // EBPF_OP_MOV64_REG pc=72 dst=r2 src=r10 offset=0 imm=0
#line 189 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=73 dst=r2 src=r0 offset=0 imm=-60
#line 164 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-60);
    // EBPF_OP_LDDW pc=74 dst=r1 src=r1 offset=0 imm=6
#line 190 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[5].address);
    // EBPF_OP_CALL pc=76 dst=r0 src=r0 offset=0 imm=1
#line 190 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[5].address(r1, r2, r3, r4, r5, context);
#line 190 "sample/cgroup_sock_addr_helpers.c"
    if ((runtime_context->helper_data[5].tail_call) && (r0 == 0)) {
#line 190 "sample/cgroup_sock_addr_helpers.c"
        return 0;
#line 190 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_JEQ_IMM pc=77 dst=r0 src=r0 offset=3 imm=0
#line 191 "sample/cgroup_sock_addr_helpers.c"
    if (r0 == IMMEDIATE(0)) {
#line 191 "sample/cgroup_sock_addr_helpers.c"
        goto label_1;
#line 191 "sample/cgroup_sock_addr_helpers.c"
    }
    // EBPF_OP_LDXDW pc=78 dst=r1 src=r0 offset=0 imm=0
#line 192 "sample/cgroup_sock_addr_helpers.c"
    READ_ONCE_64(r1, r0, OFFSET(0));
    // EBPF_OP_ADD64_IMM pc=79 dst=r1 src=r0 offset=0 imm=1
#line 192 "sample/cgroup_sock_addr_helpers.c"
    r1 += IMMEDIATE(1);
    // EBPF_OP_STXDW pc=80 dst=r10 src=r1 offset=-72 imm=0
#line 192 "sample/cgroup_sock_addr_helpers.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-72));
label_1:
    // EBPF_OP_MOV64_REG pc=81 dst=r2 src=r10 offset=0 imm=0
#line 192 "sample/cgroup_sock_addr_helpers.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=82 dst=r2 src=r0 offset=0 imm=-60
#line 194 "sample/cgroup_sock_addr_helpers.c"
    r2 += IMMEDIATE(-60);
    // EBPF_OP_MOV64_REG pc=83 dst=r3 src=r10 offset=0 imm=0
#line 194 "sample/cgroup_sock_addr_helpers.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=84 dst=r3 src=r0 offset=0 imm=-72
#line 194 "sample/cgroup_sock_addr_helpers.c"
    r3 += IMMEDIATE(-72);
    // EBPF_OP_LDDW pc=85 dst=r1 src=r1 offset=0 imm=6
#line 194 "sample/cgroup_sock_addr_helpers.c"
    r1 = POINTER(runtime_context->map_data[5].address);
    // EBPF_OP_MOV64_IMM pc=87 dst=r4 src=r0 offset=0 imm=0
#line 194 "sample/cgroup_sock_addr_helpers.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=88 dst=r0 src=r0 offset=0 imm=2
#line 194 "sample/cgroup_sock_addr_helpers.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 194 "sample/cgroup_sock_addr_helpers.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 194 "sample/cgroup_sock_addr_helpers.c"
        return 0;
#line 194 "sample/cgroup_sock_addr_helpers.c"
    }
label_2:
    // EBPF_OP_MOV64_IMM pc=89 dst=r0 src=r0 offset=0 imm=1
#line 197 "sample/cgroup_sock_addr_helpers.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_EXIT pc=90 dst=r0 src=r0 offset=0 imm=0
#line 197 "sample/cgroup_sock_addr_helpers.c"
    return r0;
#line 159 "sample/cgroup_sock_addr_helpers.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        {1, 144, 144}, // Version header.
        conditional_authorization_v4,
        "cgroup~2",
        "cgroup/connect_authorization4",
        "conditional_authorization_v4",
        conditional_authorization_v4_maps,
        1,
        conditional_authorization_v4_helpers,
        6,
        44,
        &conditional_authorization_v4_program_type_guid,
        &conditional_authorization_v4_attach_type_guid,
    },
    {
        0,
        {1, 144, 144}, // Version header.
        test_sock_addr_helpers_v4,
        "cgroup~3",
        "cgroup/connect_authorization4",
        "test_sock_addr_helpers_v4",
        test_sock_addr_helpers_v4_maps,
        6,
        test_sock_addr_helpers_v4_helpers,
        6,
        88,
        &test_sock_addr_helpers_v4_program_type_guid,
        &test_sock_addr_helpers_v4_attach_type_guid,
    },
    {
        0,
        {1, 144, 144}, // Version header.
        test_sock_addr_helpers_v6,
        "cgroup~1",
        "cgroup/connect_authorization6",
        "test_sock_addr_helpers_v6",
        test_sock_addr_helpers_v6_maps,
        6,
        test_sock_addr_helpers_v6_helpers,
        6,
        91,
        &test_sock_addr_helpers_v6_program_type_guid,
        &test_sock_addr_helpers_v6_attach_type_guid,
    },
};
#pragma data_seg(pop)

static void
_get_programs(_Outptr_result_buffer_(*count) program_entry_t** programs, _Out_ size_t* count)
{
    *programs = _programs;
    *count = 3;
}

static void
_get_version(_Out_ bpf2c_version_t* version)
{
    version->major = 1;
    version->minor = 1;
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
