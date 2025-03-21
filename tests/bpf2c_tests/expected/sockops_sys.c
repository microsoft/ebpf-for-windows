// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from sockops.o

#define NO_CRT
#include "bpf2c.h"

#include <guiddef.h>
#include <wdm.h>
#include <wsk.h>

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
RTL_QUERY_REGISTRY_ROUTINE static _bpf2c_query_registry_routine;

#define metadata_table sockops##_metadata_table

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
         56,                // Size in bytes of a map key.
         4,                 // Size in bytes of a map value.
         2,                 // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         LIBBPF_PIN_NONE,   // Pinning type for the map.
         21,                // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "connection_map"},
    {
     {0, 0},
     {
         1,                    // Current Version.
         80,                   // Struct size up to the last field.
         80,                   // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_RINGBUF, // Type of map.
         0,                    // Size in bytes of a map key.
         0,                    // Size in bytes of a map value.
         262144,               // Maximum number of entries allowed in the map.
         0,                    // Inner map index.
         LIBBPF_PIN_NONE,      // Pinning type for the map.
         27,                   // Identifier for a map template.
         0,                    // The id of the inner map template.
     },
     "audit_map"},
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

static helper_function_entry_t connection_monitor_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     19,
     "helper_id_19",
    },
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     11,
     "helper_id_11",
    },
};

static GUID connection_monitor_program_type_guid = {
    0x43fb224d, 0x68f8, 0x46d6, {0xaa, 0x3f, 0xc8, 0x56, 0x51, 0x8c, 0xbb, 0x32}};
static GUID connection_monitor_attach_type_guid = {
    0x837d02cd, 0x3251, 0x4632, {0x8d, 0x94, 0x60, 0xd3, 0xb4, 0x57, 0x69, 0xf2}};
static uint16_t connection_monitor_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "sockops")
static uint64_t
connection_monitor(void* context, const program_runtime_context_t* runtime_context)
#line 78 "sample/sockops.c"
{
#line 78 "sample/sockops.c"
    // Prologue.
#line 78 "sample/sockops.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 78 "sample/sockops.c"
    register uint64_t r0 = 0;
#line 78 "sample/sockops.c"
    register uint64_t r1 = 0;
#line 78 "sample/sockops.c"
    register uint64_t r2 = 0;
#line 78 "sample/sockops.c"
    register uint64_t r3 = 0;
#line 78 "sample/sockops.c"
    register uint64_t r4 = 0;
#line 78 "sample/sockops.c"
    register uint64_t r5 = 0;
#line 78 "sample/sockops.c"
    register uint64_t r6 = 0;
#line 78 "sample/sockops.c"
    register uint64_t r10 = 0;

#line 78 "sample/sockops.c"
    r1 = (uintptr_t)context;
#line 78 "sample/sockops.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r6 src=r0 offset=0 imm=2
#line 78 "sample/sockops.c"
    r6 = IMMEDIATE(2);
    // EBPF_OP_MOV64_IMM pc=1 dst=r2 src=r0 offset=0 imm=1
#line 78 "sample/sockops.c"
    r2 = IMMEDIATE(1);
    // EBPF_OP_LDXW pc=2 dst=r3 src=r1 offset=0 imm=0
#line 83 "sample/sockops.c"
    r3 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(0));
    // EBPF_OP_JEQ_IMM pc=3 dst=r3 src=r0 offset=8 imm=0
#line 83 "sample/sockops.c"
    if (r3 == IMMEDIATE(0)) {
#line 83 "sample/sockops.c"
        goto label_2;
#line 83 "sample/sockops.c"
    }
    // EBPF_OP_JEQ_IMM pc=4 dst=r3 src=r0 offset=5 imm=2
#line 83 "sample/sockops.c"
    if (r3 == IMMEDIATE(2)) {
#line 83 "sample/sockops.c"
        goto label_1;
#line 83 "sample/sockops.c"
    }
    // EBPF_OP_LDDW pc=5 dst=r0 src=r0 offset=0 imm=-1
#line 83 "sample/sockops.c"
    r0 = (uint64_t)4294967295;
    // EBPF_OP_JNE_IMM pc=7 dst=r3 src=r0 offset=170 imm=1
#line 83 "sample/sockops.c"
    if (r3 != IMMEDIATE(1)) {
#line 83 "sample/sockops.c"
        goto label_5;
#line 83 "sample/sockops.c"
    }
    // EBPF_OP_MOV64_IMM pc=8 dst=r2 src=r0 offset=0 imm=0
#line 83 "sample/sockops.c"
    r2 = IMMEDIATE(0);
    // EBPF_OP_JA pc=9 dst=r0 src=r0 offset=2 imm=0
#line 83 "sample/sockops.c"
    goto label_2;
label_1:
    // EBPF_OP_MOV64_IMM pc=10 dst=r2 src=r0 offset=0 imm=0
#line 83 "sample/sockops.c"
    r2 = IMMEDIATE(0);
    // EBPF_OP_MOV64_IMM pc=11 dst=r6 src=r0 offset=0 imm=0
#line 83 "sample/sockops.c"
    r6 = IMMEDIATE(0);
label_2:
    // EBPF_OP_LDXW pc=12 dst=r3 src=r1 offset=4 imm=0
#line 100 "sample/sockops.c"
    r3 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(4));
    // EBPF_OP_JNE_IMM pc=13 dst=r3 src=r0 offset=37 imm=2
#line 100 "sample/sockops.c"
    if (r3 != IMMEDIATE(2)) {
#line 100 "sample/sockops.c"
        goto label_3;
#line 100 "sample/sockops.c"
    }
    // EBPF_OP_MOV64_IMM pc=14 dst=r3 src=r0 offset=0 imm=0
#line 100 "sample/sockops.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=15 dst=r10 src=r3 offset=-8 imm=0
#line 36 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint64_t)r3;
    // EBPF_OP_STXDW pc=16 dst=r10 src=r3 offset=-16 imm=0
#line 36 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r3;
    // EBPF_OP_STXDW pc=17 dst=r10 src=r3 offset=-24 imm=0
#line 36 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r3;
    // EBPF_OP_STXDW pc=18 dst=r10 src=r3 offset=-32 imm=0
#line 36 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r3;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r3 offset=-40 imm=0
#line 36 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r3;
    // EBPF_OP_STXDW pc=20 dst=r10 src=r3 offset=-48 imm=0
#line 36 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r3;
    // EBPF_OP_STXDW pc=21 dst=r10 src=r3 offset=-56 imm=0
#line 36 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r3;
    // EBPF_OP_STXDW pc=22 dst=r10 src=r3 offset=-64 imm=0
#line 36 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r3;
    // EBPF_OP_STXDW pc=23 dst=r10 src=r3 offset=-72 imm=0
#line 36 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r3;
    // EBPF_OP_LDXW pc=24 dst=r3 src=r1 offset=8 imm=0
#line 38 "sample/sockops.c"
    r3 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(8));
    // EBPF_OP_STXW pc=25 dst=r10 src=r3 offset=-72 imm=0
#line 38 "sample/sockops.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint32_t)r3;
    // EBPF_OP_LDXW pc=26 dst=r3 src=r1 offset=24 imm=0
#line 39 "sample/sockops.c"
    r3 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(24));
    // EBPF_OP_STXH pc=27 dst=r10 src=r3 offset=-56 imm=0
#line 39 "sample/sockops.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint16_t)r3;
    // EBPF_OP_LDXW pc=28 dst=r3 src=r1 offset=28 imm=0
#line 40 "sample/sockops.c"
    r3 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(28));
    // EBPF_OP_STXW pc=29 dst=r10 src=r3 offset=-52 imm=0
#line 40 "sample/sockops.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-52)) = (uint32_t)r3;
    // EBPF_OP_OR64_REG pc=30 dst=r6 src=r2 offset=0 imm=0
#line 47 "sample/sockops.c"
    r6 |= r2;
    // EBPF_OP_LDXW pc=31 dst=r2 src=r1 offset=44 imm=0
#line 41 "sample/sockops.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(44));
    // EBPF_OP_STXH pc=32 dst=r10 src=r2 offset=-36 imm=0
#line 41 "sample/sockops.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-36)) = (uint16_t)r2;
    // EBPF_OP_LDXB pc=33 dst=r2 src=r1 offset=48 imm=0
#line 42 "sample/sockops.c"
    r2 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(48));
    // EBPF_OP_STXW pc=34 dst=r10 src=r2 offset=-32 imm=0
#line 42 "sample/sockops.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint32_t)r2;
    // EBPF_OP_LDXDW pc=35 dst=r1 src=r1 offset=56 imm=0
#line 43 "sample/sockops.c"
    r1 = *(uint64_t*)(uintptr_t)(r1 + OFFSET(56));
    // EBPF_OP_STXDW pc=36 dst=r10 src=r1 offset=-24 imm=0
#line 43 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_CALL pc=37 dst=r0 src=r0 offset=0 imm=19
#line 44 "sample/sockops.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 44 "sample/sockops.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 44 "sample/sockops.c"
        return 0;
#line 44 "sample/sockops.c"
    }
    // EBPF_OP_STXB pc=38 dst=r10 src=r6 offset=-8 imm=0
#line 48 "sample/sockops.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r6;
    // EBPF_OP_RSH64_IMM pc=39 dst=r0 src=r0 offset=0 imm=32
#line 46 "sample/sockops.c"
    r0 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_STXDW pc=40 dst=r10 src=r0 offset=-16 imm=0
#line 46 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r0;
    // EBPF_OP_MOV64_REG pc=41 dst=r2 src=r10 offset=0 imm=0
#line 46 "sample/sockops.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=42 dst=r2 src=r0 offset=0 imm=-72
#line 46 "sample/sockops.c"
    r2 += IMMEDIATE(-72);
    // EBPF_OP_LDDW pc=43 dst=r1 src=r1 offset=0 imm=1
#line 26 "sample/sockops.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_CALL pc=45 dst=r0 src=r0 offset=0 imm=1
#line 26 "sample/sockops.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 26 "sample/sockops.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 26 "sample/sockops.c"
        return 0;
#line 26 "sample/sockops.c"
    }
    // EBPF_OP_MOV64_REG pc=46 dst=r1 src=r0 offset=0 imm=0
#line 26 "sample/sockops.c"
    r1 = r0;
    // EBPF_OP_LDDW pc=47 dst=r0 src=r0 offset=0 imm=-1
#line 26 "sample/sockops.c"
    r0 = (uint64_t)4294967295;
    // EBPF_OP_JEQ_IMM pc=49 dst=r1 src=r0 offset=128 imm=0
#line 26 "sample/sockops.c"
    if (r1 == IMMEDIATE(0)) {
#line 26 "sample/sockops.c"
        goto label_5;
#line 26 "sample/sockops.c"
    }
    // EBPF_OP_JA pc=50 dst=r0 src=r0 offset=120 imm=0
#line 26 "sample/sockops.c"
    goto label_4;
label_3:
    // EBPF_OP_MOV64_IMM pc=51 dst=r3 src=r0 offset=0 imm=0
#line 26 "sample/sockops.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=52 dst=r10 src=r3 offset=-8 imm=0
#line 56 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint64_t)r3;
    // EBPF_OP_STXDW pc=53 dst=r10 src=r3 offset=-16 imm=0
#line 56 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r3;
    // EBPF_OP_STXDW pc=54 dst=r10 src=r3 offset=-24 imm=0
#line 56 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r3;
    // EBPF_OP_STXDW pc=55 dst=r10 src=r3 offset=-32 imm=0
#line 56 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r3;
    // EBPF_OP_STXDW pc=56 dst=r10 src=r3 offset=-40 imm=0
#line 56 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint64_t)r3;
    // EBPF_OP_STXDW pc=57 dst=r10 src=r3 offset=-48 imm=0
#line 56 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint64_t)r3;
    // EBPF_OP_STXDW pc=58 dst=r10 src=r3 offset=-56 imm=0
#line 56 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint64_t)r3;
    // EBPF_OP_LDXB pc=59 dst=r4 src=r1 offset=17 imm=0
#line 60 "sample/sockops.c"
    r4 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(17));
    // EBPF_OP_LSH64_IMM pc=60 dst=r4 src=r0 offset=0 imm=8
#line 60 "sample/sockops.c"
    r4 <<= (IMMEDIATE(8) & 63);
    // EBPF_OP_LDXB pc=61 dst=r3 src=r1 offset=16 imm=0
#line 60 "sample/sockops.c"
    r3 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(16));
    // EBPF_OP_OR64_REG pc=62 dst=r4 src=r3 offset=0 imm=0
#line 60 "sample/sockops.c"
    r4 |= r3;
    // EBPF_OP_LDXB pc=63 dst=r5 src=r1 offset=18 imm=0
#line 60 "sample/sockops.c"
    r5 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(18));
    // EBPF_OP_LSH64_IMM pc=64 dst=r5 src=r0 offset=0 imm=16
#line 60 "sample/sockops.c"
    r5 <<= (IMMEDIATE(16) & 63);
    // EBPF_OP_LDXB pc=65 dst=r3 src=r1 offset=19 imm=0
#line 60 "sample/sockops.c"
    r3 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(19));
    // EBPF_OP_LSH64_IMM pc=66 dst=r3 src=r0 offset=0 imm=24
#line 60 "sample/sockops.c"
    r3 <<= (IMMEDIATE(24) & 63);
    // EBPF_OP_OR64_REG pc=67 dst=r3 src=r5 offset=0 imm=0
#line 60 "sample/sockops.c"
    r3 |= r5;
    // EBPF_OP_OR64_REG pc=68 dst=r3 src=r4 offset=0 imm=0
#line 60 "sample/sockops.c"
    r3 |= r4;
    // EBPF_OP_LDXB pc=69 dst=r5 src=r1 offset=21 imm=0
#line 60 "sample/sockops.c"
    r5 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(21));
    // EBPF_OP_LSH64_IMM pc=70 dst=r5 src=r0 offset=0 imm=8
#line 60 "sample/sockops.c"
    r5 <<= (IMMEDIATE(8) & 63);
    // EBPF_OP_LDXB pc=71 dst=r4 src=r1 offset=20 imm=0
#line 60 "sample/sockops.c"
    r4 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(20));
    // EBPF_OP_OR64_REG pc=72 dst=r5 src=r4 offset=0 imm=0
#line 60 "sample/sockops.c"
    r5 |= r4;
    // EBPF_OP_LDXB pc=73 dst=r0 src=r1 offset=22 imm=0
#line 60 "sample/sockops.c"
    r0 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(22));
    // EBPF_OP_LSH64_IMM pc=74 dst=r0 src=r0 offset=0 imm=16
#line 60 "sample/sockops.c"
    r0 <<= (IMMEDIATE(16) & 63);
    // EBPF_OP_LDXB pc=75 dst=r4 src=r1 offset=23 imm=0
#line 60 "sample/sockops.c"
    r4 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(23));
    // EBPF_OP_LSH64_IMM pc=76 dst=r4 src=r0 offset=0 imm=24
#line 60 "sample/sockops.c"
    r4 <<= (IMMEDIATE(24) & 63);
    // EBPF_OP_OR64_REG pc=77 dst=r4 src=r0 offset=0 imm=0
#line 60 "sample/sockops.c"
    r4 |= r0;
    // EBPF_OP_OR64_REG pc=78 dst=r4 src=r5 offset=0 imm=0
#line 60 "sample/sockops.c"
    r4 |= r5;
    // EBPF_OP_LSH64_IMM pc=79 dst=r4 src=r0 offset=0 imm=32
#line 60 "sample/sockops.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_OR64_REG pc=80 dst=r4 src=r3 offset=0 imm=0
#line 60 "sample/sockops.c"
    r4 |= r3;
    // EBPF_OP_LDXB pc=81 dst=r5 src=r1 offset=9 imm=0
#line 60 "sample/sockops.c"
    r5 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(9));
    // EBPF_OP_LSH64_IMM pc=82 dst=r5 src=r0 offset=0 imm=8
#line 60 "sample/sockops.c"
    r5 <<= (IMMEDIATE(8) & 63);
    // EBPF_OP_LDXB pc=83 dst=r3 src=r1 offset=8 imm=0
#line 60 "sample/sockops.c"
    r3 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(8));
    // EBPF_OP_OR64_REG pc=84 dst=r5 src=r3 offset=0 imm=0
#line 60 "sample/sockops.c"
    r5 |= r3;
    // EBPF_OP_LDXB pc=85 dst=r0 src=r1 offset=10 imm=0
#line 60 "sample/sockops.c"
    r0 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(10));
    // EBPF_OP_LSH64_IMM pc=86 dst=r0 src=r0 offset=0 imm=16
#line 60 "sample/sockops.c"
    r0 <<= (IMMEDIATE(16) & 63);
    // EBPF_OP_LDXB pc=87 dst=r3 src=r1 offset=11 imm=0
#line 60 "sample/sockops.c"
    r3 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(11));
    // EBPF_OP_LSH64_IMM pc=88 dst=r3 src=r0 offset=0 imm=24
#line 60 "sample/sockops.c"
    r3 <<= (IMMEDIATE(24) & 63);
    // EBPF_OP_OR64_REG pc=89 dst=r3 src=r0 offset=0 imm=0
#line 60 "sample/sockops.c"
    r3 |= r0;
    // EBPF_OP_OR64_REG pc=90 dst=r6 src=r2 offset=0 imm=0
#line 70 "sample/sockops.c"
    r6 |= r2;
    // EBPF_OP_STXDW pc=91 dst=r10 src=r4 offset=-64 imm=0
#line 60 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint64_t)r4;
    // EBPF_OP_OR64_REG pc=92 dst=r3 src=r5 offset=0 imm=0
#line 60 "sample/sockops.c"
    r3 |= r5;
    // EBPF_OP_LDXB pc=93 dst=r2 src=r1 offset=13 imm=0
#line 60 "sample/sockops.c"
    r2 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(13));
    // EBPF_OP_LSH64_IMM pc=94 dst=r2 src=r0 offset=0 imm=8
#line 60 "sample/sockops.c"
    r2 <<= (IMMEDIATE(8) & 63);
    // EBPF_OP_LDXB pc=95 dst=r4 src=r1 offset=12 imm=0
#line 60 "sample/sockops.c"
    r4 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(12));
    // EBPF_OP_OR64_REG pc=96 dst=r2 src=r4 offset=0 imm=0
#line 60 "sample/sockops.c"
    r2 |= r4;
    // EBPF_OP_LDXB pc=97 dst=r4 src=r1 offset=14 imm=0
#line 60 "sample/sockops.c"
    r4 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(14));
    // EBPF_OP_LSH64_IMM pc=98 dst=r4 src=r0 offset=0 imm=16
#line 60 "sample/sockops.c"
    r4 <<= (IMMEDIATE(16) & 63);
    // EBPF_OP_LDXB pc=99 dst=r5 src=r1 offset=15 imm=0
#line 60 "sample/sockops.c"
    r5 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(15));
    // EBPF_OP_LSH64_IMM pc=100 dst=r5 src=r0 offset=0 imm=24
#line 60 "sample/sockops.c"
    r5 <<= (IMMEDIATE(24) & 63);
    // EBPF_OP_OR64_REG pc=101 dst=r5 src=r4 offset=0 imm=0
#line 60 "sample/sockops.c"
    r5 |= r4;
    // EBPF_OP_OR64_REG pc=102 dst=r5 src=r2 offset=0 imm=0
#line 60 "sample/sockops.c"
    r5 |= r2;
    // EBPF_OP_LSH64_IMM pc=103 dst=r5 src=r0 offset=0 imm=32
#line 60 "sample/sockops.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_OR64_REG pc=104 dst=r5 src=r3 offset=0 imm=0
#line 60 "sample/sockops.c"
    r5 |= r3;
    // EBPF_OP_STXDW pc=105 dst=r10 src=r5 offset=-72 imm=0
#line 60 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r5;
    // EBPF_OP_LDXW pc=106 dst=r2 src=r1 offset=24 imm=0
#line 61 "sample/sockops.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(24));
    // EBPF_OP_STXH pc=107 dst=r10 src=r2 offset=-56 imm=0
#line 61 "sample/sockops.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-56)) = (uint16_t)r2;
    // EBPF_OP_LDXB pc=108 dst=r3 src=r1 offset=41 imm=0
#line 63 "sample/sockops.c"
    r3 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(41));
    // EBPF_OP_LSH64_IMM pc=109 dst=r3 src=r0 offset=0 imm=8
#line 63 "sample/sockops.c"
    r3 <<= (IMMEDIATE(8) & 63);
    // EBPF_OP_LDXB pc=110 dst=r2 src=r1 offset=40 imm=0
#line 63 "sample/sockops.c"
    r2 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(40));
    // EBPF_OP_OR64_REG pc=111 dst=r3 src=r2 offset=0 imm=0
#line 63 "sample/sockops.c"
    r3 |= r2;
    // EBPF_OP_LDXB pc=112 dst=r4 src=r1 offset=42 imm=0
#line 63 "sample/sockops.c"
    r4 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(42));
    // EBPF_OP_LSH64_IMM pc=113 dst=r4 src=r0 offset=0 imm=16
#line 63 "sample/sockops.c"
    r4 <<= (IMMEDIATE(16) & 63);
    // EBPF_OP_LDXB pc=114 dst=r2 src=r1 offset=43 imm=0
#line 63 "sample/sockops.c"
    r2 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(43));
    // EBPF_OP_LSH64_IMM pc=115 dst=r2 src=r0 offset=0 imm=24
#line 63 "sample/sockops.c"
    r2 <<= (IMMEDIATE(24) & 63);
    // EBPF_OP_OR64_REG pc=116 dst=r2 src=r4 offset=0 imm=0
#line 63 "sample/sockops.c"
    r2 |= r4;
    // EBPF_OP_LDXB pc=117 dst=r5 src=r1 offset=29 imm=0
#line 63 "sample/sockops.c"
    r5 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(29));
    // EBPF_OP_LSH64_IMM pc=118 dst=r5 src=r0 offset=0 imm=8
#line 63 "sample/sockops.c"
    r5 <<= (IMMEDIATE(8) & 63);
    // EBPF_OP_LDXB pc=119 dst=r4 src=r1 offset=28 imm=0
#line 63 "sample/sockops.c"
    r4 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(28));
    // EBPF_OP_OR64_REG pc=120 dst=r5 src=r4 offset=0 imm=0
#line 63 "sample/sockops.c"
    r5 |= r4;
    // EBPF_OP_LDXB pc=121 dst=r0 src=r1 offset=30 imm=0
#line 63 "sample/sockops.c"
    r0 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(30));
    // EBPF_OP_LSH64_IMM pc=122 dst=r0 src=r0 offset=0 imm=16
#line 63 "sample/sockops.c"
    r0 <<= (IMMEDIATE(16) & 63);
    // EBPF_OP_LDXB pc=123 dst=r4 src=r1 offset=31 imm=0
#line 63 "sample/sockops.c"
    r4 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(31));
    // EBPF_OP_LSH64_IMM pc=124 dst=r4 src=r0 offset=0 imm=24
#line 63 "sample/sockops.c"
    r4 <<= (IMMEDIATE(24) & 63);
    // EBPF_OP_OR64_REG pc=125 dst=r4 src=r0 offset=0 imm=0
#line 63 "sample/sockops.c"
    r4 |= r0;
    // EBPF_OP_OR64_REG pc=126 dst=r4 src=r5 offset=0 imm=0
#line 63 "sample/sockops.c"
    r4 |= r5;
    // EBPF_OP_OR64_REG pc=127 dst=r2 src=r3 offset=0 imm=0
#line 63 "sample/sockops.c"
    r2 |= r3;
    // EBPF_OP_LDXB pc=128 dst=r3 src=r1 offset=37 imm=0
#line 63 "sample/sockops.c"
    r3 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(37));
    // EBPF_OP_LSH64_IMM pc=129 dst=r3 src=r0 offset=0 imm=8
#line 63 "sample/sockops.c"
    r3 <<= (IMMEDIATE(8) & 63);
    // EBPF_OP_LDXB pc=130 dst=r5 src=r1 offset=36 imm=0
#line 63 "sample/sockops.c"
    r5 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(36));
    // EBPF_OP_OR64_REG pc=131 dst=r3 src=r5 offset=0 imm=0
#line 63 "sample/sockops.c"
    r3 |= r5;
    // EBPF_OP_LDXB pc=132 dst=r5 src=r1 offset=38 imm=0
#line 63 "sample/sockops.c"
    r5 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(38));
    // EBPF_OP_LSH64_IMM pc=133 dst=r5 src=r0 offset=0 imm=16
#line 63 "sample/sockops.c"
    r5 <<= (IMMEDIATE(16) & 63);
    // EBPF_OP_LDXB pc=134 dst=r0 src=r1 offset=39 imm=0
#line 63 "sample/sockops.c"
    r0 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(39));
    // EBPF_OP_LSH64_IMM pc=135 dst=r0 src=r0 offset=0 imm=24
#line 63 "sample/sockops.c"
    r0 <<= (IMMEDIATE(24) & 63);
    // EBPF_OP_OR64_REG pc=136 dst=r0 src=r5 offset=0 imm=0
#line 63 "sample/sockops.c"
    r0 |= r5;
    // EBPF_OP_OR64_REG pc=137 dst=r0 src=r3 offset=0 imm=0
#line 63 "sample/sockops.c"
    r0 |= r3;
    // EBPF_OP_STXW pc=138 dst=r10 src=r0 offset=-44 imm=0
#line 63 "sample/sockops.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-44)) = (uint32_t)r0;
    // EBPF_OP_STXW pc=139 dst=r10 src=r2 offset=-40 imm=0
#line 63 "sample/sockops.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-40)) = (uint32_t)r2;
    // EBPF_OP_STXW pc=140 dst=r10 src=r4 offset=-52 imm=0
#line 63 "sample/sockops.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-52)) = (uint32_t)r4;
    // EBPF_OP_LDXB pc=141 dst=r2 src=r1 offset=33 imm=0
#line 63 "sample/sockops.c"
    r2 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(33));
    // EBPF_OP_LSH64_IMM pc=142 dst=r2 src=r0 offset=0 imm=8
#line 63 "sample/sockops.c"
    r2 <<= (IMMEDIATE(8) & 63);
    // EBPF_OP_LDXB pc=143 dst=r3 src=r1 offset=32 imm=0
#line 63 "sample/sockops.c"
    r3 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(32));
    // EBPF_OP_OR64_REG pc=144 dst=r2 src=r3 offset=0 imm=0
#line 63 "sample/sockops.c"
    r2 |= r3;
    // EBPF_OP_LDXB pc=145 dst=r3 src=r1 offset=34 imm=0
#line 63 "sample/sockops.c"
    r3 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(34));
    // EBPF_OP_LSH64_IMM pc=146 dst=r3 src=r0 offset=0 imm=16
#line 63 "sample/sockops.c"
    r3 <<= (IMMEDIATE(16) & 63);
    // EBPF_OP_LDXB pc=147 dst=r4 src=r1 offset=35 imm=0
#line 63 "sample/sockops.c"
    r4 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(35));
    // EBPF_OP_LSH64_IMM pc=148 dst=r4 src=r0 offset=0 imm=24
#line 63 "sample/sockops.c"
    r4 <<= (IMMEDIATE(24) & 63);
    // EBPF_OP_OR64_REG pc=149 dst=r4 src=r3 offset=0 imm=0
#line 63 "sample/sockops.c"
    r4 |= r3;
    // EBPF_OP_OR64_REG pc=150 dst=r4 src=r2 offset=0 imm=0
#line 63 "sample/sockops.c"
    r4 |= r2;
    // EBPF_OP_STXW pc=151 dst=r10 src=r4 offset=-48 imm=0
#line 63 "sample/sockops.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-48)) = (uint32_t)r4;
    // EBPF_OP_LDXW pc=152 dst=r2 src=r1 offset=44 imm=0
#line 64 "sample/sockops.c"
    r2 = *(uint32_t*)(uintptr_t)(r1 + OFFSET(44));
    // EBPF_OP_STXH pc=153 dst=r10 src=r2 offset=-36 imm=0
#line 64 "sample/sockops.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-36)) = (uint16_t)r2;
    // EBPF_OP_LDXB pc=154 dst=r2 src=r1 offset=48 imm=0
#line 65 "sample/sockops.c"
    r2 = *(uint8_t*)(uintptr_t)(r1 + OFFSET(48));
    // EBPF_OP_STXW pc=155 dst=r10 src=r2 offset=-32 imm=0
#line 65 "sample/sockops.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint32_t)r2;
    // EBPF_OP_LDXDW pc=156 dst=r1 src=r1 offset=56 imm=0
#line 66 "sample/sockops.c"
    r1 = *(uint64_t*)(uintptr_t)(r1 + OFFSET(56));
    // EBPF_OP_STXDW pc=157 dst=r10 src=r1 offset=-24 imm=0
#line 66 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-24)) = (uint64_t)r1;
    // EBPF_OP_CALL pc=158 dst=r0 src=r0 offset=0 imm=19
#line 67 "sample/sockops.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 67 "sample/sockops.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 67 "sample/sockops.c"
        return 0;
#line 67 "sample/sockops.c"
    }
    // EBPF_OP_STXB pc=159 dst=r10 src=r6 offset=-8 imm=0
#line 71 "sample/sockops.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint8_t)r6;
    // EBPF_OP_RSH64_IMM pc=160 dst=r0 src=r0 offset=0 imm=32
#line 69 "sample/sockops.c"
    r0 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_STXDW pc=161 dst=r10 src=r0 offset=-16 imm=0
#line 69 "sample/sockops.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r0;
    // EBPF_OP_MOV64_REG pc=162 dst=r2 src=r10 offset=0 imm=0
#line 69 "sample/sockops.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=163 dst=r2 src=r0 offset=0 imm=-72
#line 69 "sample/sockops.c"
    r2 += IMMEDIATE(-72);
    // EBPF_OP_LDDW pc=164 dst=r1 src=r1 offset=0 imm=1
#line 26 "sample/sockops.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_CALL pc=166 dst=r0 src=r0 offset=0 imm=1
#line 26 "sample/sockops.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 26 "sample/sockops.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 26 "sample/sockops.c"
        return 0;
#line 26 "sample/sockops.c"
    }
    // EBPF_OP_MOV64_REG pc=167 dst=r1 src=r0 offset=0 imm=0
#line 26 "sample/sockops.c"
    r1 = r0;
    // EBPF_OP_LDDW pc=168 dst=r0 src=r0 offset=0 imm=-1
#line 26 "sample/sockops.c"
    r0 = (uint64_t)4294967295;
    // EBPF_OP_JEQ_IMM pc=170 dst=r1 src=r0 offset=7 imm=0
#line 26 "sample/sockops.c"
    if (r1 == IMMEDIATE(0)) {
#line 26 "sample/sockops.c"
        goto label_5;
#line 26 "sample/sockops.c"
    }
label_4:
    // EBPF_OP_MOV64_REG pc=171 dst=r2 src=r10 offset=0 imm=0
#line 26 "sample/sockops.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=172 dst=r2 src=r0 offset=0 imm=-72
#line 100 "sample/sockops.c"
    r2 += IMMEDIATE(-72);
    // EBPF_OP_LDDW pc=173 dst=r1 src=r1 offset=0 imm=2
#line 100 "sample/sockops.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_MOV64_IMM pc=175 dst=r3 src=r0 offset=0 imm=72
#line 100 "sample/sockops.c"
    r3 = IMMEDIATE(72);
    // EBPF_OP_MOV64_IMM pc=176 dst=r4 src=r0 offset=0 imm=0
#line 100 "sample/sockops.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=177 dst=r0 src=r0 offset=0 imm=11
#line 100 "sample/sockops.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 100 "sample/sockops.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 100 "sample/sockops.c"
        return 0;
#line 100 "sample/sockops.c"
    }
label_5:
    // EBPF_OP_EXIT pc=178 dst=r0 src=r0 offset=0 imm=0
#line 103 "sample/sockops.c"
    return r0;
#line 78 "sample/sockops.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        {1, 144, 144}, // Version header.
        connection_monitor,
        "sockops",
        "sockops",
        "connection_monitor",
        connection_monitor_maps,
        2,
        connection_monitor_helpers,
        3,
        179,
        &connection_monitor_program_type_guid,
        &connection_monitor_attach_type_guid,
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

metadata_table_t sockops_metadata_table = {
    sizeof(metadata_table_t),
    _get_programs,
    _get_maps,
    _get_hash,
    _get_version,
    _get_map_initial_values,
    _get_global_variable_sections,
};
