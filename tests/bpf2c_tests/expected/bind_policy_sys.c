// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from bind_policy.o

#define NO_CRT
#include "bpf2c.h"

#include <guiddef.h>
#include <wdm.h>
#include <wsk.h>

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
RTL_QUERY_REGISTRY_ROUTINE static _bpf2c_query_registry_routine;

#define metadata_table bind_policy##_metadata_table

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
         16,                // Size in bytes of a map key.
         4,                 // Size in bytes of a map value.
         100,               // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         LIBBPF_PIN_NONE,   // Pinning type for the map.
         21,                // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "bind_policy_map"},
    {
     {0, 0},
     {
         1,                 // Current Version.
         80,                // Struct size up to the last field.
         80,                // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_HASH, // Type of map.
         8,                 // Size in bytes of a map key.
         8,                 // Size in bytes of a map value.
         1000,              // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         LIBBPF_PIN_NONE,   // Pinning type for the map.
         31,                // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "bind_audit_map"},
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

static helper_function_entry_t authorize_bind_helpers[] = {
    {
     {1, 40, 40}, // Version header.
     9,
     "helper_id_9",
    },
    {
     {1, 40, 40}, // Version header.
     2,
     "helper_id_2",
    },
    {
     {1, 40, 40}, // Version header.
     15,
     "helper_id_15",
    },
    {
     {1, 40, 40}, // Version header.
     1,
     "helper_id_1",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
};

static GUID authorize_bind_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID authorize_bind_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
static uint16_t authorize_bind_maps[] = {
    0,
    1,
};

#pragma code_seg(push, "bind")
static uint64_t
authorize_bind(void* context, const program_runtime_context_t* runtime_context)
#line 226 "sample/bind_policy.c"
{
#line 226 "sample/bind_policy.c"
    // Prologue.
#line 226 "sample/bind_policy.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 226 "sample/bind_policy.c"
    register uint64_t r0 = 0;
#line 226 "sample/bind_policy.c"
    register uint64_t r1 = 0;
#line 226 "sample/bind_policy.c"
    register uint64_t r2 = 0;
#line 226 "sample/bind_policy.c"
    register uint64_t r3 = 0;
#line 226 "sample/bind_policy.c"
    register uint64_t r4 = 0;
#line 226 "sample/bind_policy.c"
    register uint64_t r5 = 0;
#line 226 "sample/bind_policy.c"
    register uint64_t r6 = 0;
#line 226 "sample/bind_policy.c"
    register uint64_t r7 = 0;
#line 226 "sample/bind_policy.c"
    register uint64_t r8 = 0;
#line 226 "sample/bind_policy.c"
    register uint64_t r10 = 0;

#line 226 "sample/bind_policy.c"
    r1 = (uintptr_t)context;
#line 226 "sample/bind_policy.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_REG pc=0 dst=r6 src=r1 offset=0 imm=0
#line 226 "sample/bind_policy.c"
    r6 = r1;
    // EBPF_OP_LDXW pc=1 dst=r1 src=r6 offset=44 imm=0
#line 229 "sample/bind_policy.c"
    READ_ONCE_32(r1, r6, OFFSET(44));
    // EBPF_OP_JEQ_IMM pc=2 dst=r1 src=r0 offset=17 imm=0
#line 229 "sample/bind_policy.c"
    if (r1 == IMMEDIATE(0)) {
#line 229 "sample/bind_policy.c"
        goto label_1;
#line 229 "sample/bind_policy.c"
    }
    // EBPF_OP_CALL pc=3 dst=r0 src=r0 offset=0 imm=9
#line 121 "sample/bind_policy.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 121 "sample/bind_policy.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 121 "sample/bind_policy.c"
        return 0;
#line 121 "sample/bind_policy.c"
    }
    // EBPF_OP_STXDW pc=4 dst=r10 src=r0 offset=-96 imm=0
#line 121 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r0, OFFSET(-96));
    // EBPF_OP_LDDW pc=5 dst=r1 src=r0 offset=0 imm=0
#line 121 "sample/bind_policy.c"
    r1 = (uint64_t)4294967296;
    // EBPF_OP_STXDW pc=7 dst=r10 src=r1 offset=-24 imm=0
#line 122 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
    // EBPF_OP_LDXH pc=8 dst=r1 src=r6 offset=26 imm=0
#line 125 "sample/bind_policy.c"
    READ_ONCE_16(r1, r6, OFFSET(26));
    // EBPF_OP_STXH pc=9 dst=r10 src=r1 offset=-24 imm=0
#line 125 "sample/bind_policy.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-24));
    // EBPF_OP_MOV64_REG pc=10 dst=r2 src=r10 offset=0 imm=0
#line 125 "sample/bind_policy.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=11 dst=r2 src=r0 offset=0 imm=-96
#line 125 "sample/bind_policy.c"
    r2 += IMMEDIATE(-96);
    // EBPF_OP_MOV64_REG pc=12 dst=r3 src=r10 offset=0 imm=0
#line 125 "sample/bind_policy.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=13 dst=r3 src=r0 offset=0 imm=-24
#line 125 "sample/bind_policy.c"
    r3 += IMMEDIATE(-24);
    // EBPF_OP_LDDW pc=14 dst=r1 src=r1 offset=0 imm=2
#line 129 "sample/bind_policy.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_MOV64_IMM pc=16 dst=r4 src=r0 offset=0 imm=0
#line 129 "sample/bind_policy.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=17 dst=r0 src=r0 offset=0 imm=2
#line 129 "sample/bind_policy.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 129 "sample/bind_policy.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 129 "sample/bind_policy.c"
        return 0;
#line 129 "sample/bind_policy.c"
    }
    // EBPF_OP_MOV64_IMM pc=18 dst=r8 src=r0 offset=0 imm=1
#line 129 "sample/bind_policy.c"
    r8 = IMMEDIATE(1);
    // EBPF_OP_JA pc=19 dst=r0 src=r0 offset=157 imm=0
#line 129 "sample/bind_policy.c"
    goto label_7;
label_1:
    // EBPF_OP_MOV64_IMM pc=20 dst=r8 src=r0 offset=0 imm=0
#line 129 "sample/bind_policy.c"
    r8 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=21 dst=r10 src=r8 offset=-16 imm=0
#line 149 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r8, OFFSET(-16));
    // EBPF_OP_LDXDW pc=22 dst=r3 src=r6 offset=16 imm=0
#line 161 "sample/bind_policy.c"
    READ_ONCE_64(r3, r6, OFFSET(16));
    // EBPF_OP_LDXH pc=23 dst=r4 src=r6 offset=26 imm=0
#line 154 "sample/bind_policy.c"
    READ_ONCE_16(r4, r6, OFFSET(26));
    // EBPF_OP_STXH pc=24 dst=r10 src=r4 offset=-16 imm=0
#line 162 "sample/bind_policy.c"
    WRITE_ONCE_16(r10, (uint16_t)r4, OFFSET(-16));
    // EBPF_OP_STXDW pc=25 dst=r10 src=r3 offset=-24 imm=0
#line 161 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r3, OFFSET(-24));
    // EBPF_OP_LDXB pc=26 dst=r5 src=r6 offset=48 imm=0
#line 163 "sample/bind_policy.c"
    READ_ONCE_8(r5, r6, OFFSET(48));
    // EBPF_OP_STXB pc=27 dst=r10 src=r5 offset=-14 imm=0
#line 163 "sample/bind_policy.c"
    WRITE_ONCE_8(r10, (uint8_t)r5, OFFSET(-14));
    // EBPF_OP_STXB pc=28 dst=r10 src=r8 offset=-32 imm=0
#line 164 "sample/bind_policy.c"
    WRITE_ONCE_8(r10, (uint8_t)r8, OFFSET(-32));
    // EBPF_OP_LDDW pc=29 dst=r1 src=r0 offset=0 imm=1819239279
#line 164 "sample/bind_policy.c"
    r1 = (uint64_t)753549458396898159;
    // EBPF_OP_STXDW pc=31 dst=r10 src=r1 offset=-40 imm=0
#line 164 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-40));
    // EBPF_OP_LDDW pc=32 dst=r1 src=r0 offset=0 imm=539765108
#line 164 "sample/bind_policy.c"
    r1 = (uint64_t)8390050319277238644;
    // EBPF_OP_STXDW pc=34 dst=r10 src=r1 offset=-48 imm=0
#line 164 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-48));
    // EBPF_OP_LDDW pc=35 dst=r1 src=r0 offset=0 imm=1965374836
#line 164 "sample/bind_policy.c"
    r1 = (uint64_t)7308823365138333044;
    // EBPF_OP_STXDW pc=37 dst=r10 src=r1 offset=-56 imm=0
#line 164 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-56));
    // EBPF_OP_LDDW pc=38 dst=r1 src=r0 offset=0 imm=745892972
#line 164 "sample/bind_policy.c"
    r1 = (uint64_t)8245897541853736044;
    // EBPF_OP_STXDW pc=40 dst=r10 src=r1 offset=-64 imm=0
#line 164 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-64));
    // EBPF_OP_LDDW pc=41 dst=r1 src=r0 offset=0 imm=1344303727
#line 164 "sample/bind_policy.c"
    r1 = (uint64_t)2683376034650288751;
    // EBPF_OP_STXDW pc=43 dst=r10 src=r1 offset=-72 imm=0
#line 164 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-72));
    // EBPF_OP_LDDW pc=44 dst=r1 src=r0 offset=0 imm=1768714096
#line 164 "sample/bind_policy.c"
    r1 = (uint64_t)7359015259000827760;
    // EBPF_OP_STXDW pc=46 dst=r10 src=r1 offset=-80 imm=0
#line 164 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-80));
    // EBPF_OP_LDDW pc=47 dst=r1 src=r0 offset=0 imm=1646293109
#line 164 "sample/bind_policy.c"
    r1 = (uint64_t)2334111905781674101;
    // EBPF_OP_STXDW pc=49 dst=r10 src=r1 offset=-88 imm=0
#line 164 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
    // EBPF_OP_LDDW pc=50 dst=r1 src=r0 offset=0 imm=1802465100
#line 164 "sample/bind_policy.c"
    r1 = (uint64_t)2334956330867978060;
    // EBPF_OP_STXDW pc=52 dst=r10 src=r1 offset=-96 imm=0
#line 164 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
    // EBPF_OP_MOV64_REG pc=53 dst=r1 src=r10 offset=0 imm=0
#line 164 "sample/bind_policy.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=54 dst=r1 src=r0 offset=0 imm=-96
#line 164 "sample/bind_policy.c"
    r1 += IMMEDIATE(-96);
    // EBPF_OP_MOV64_IMM pc=55 dst=r2 src=r0 offset=0 imm=65
#line 164 "sample/bind_policy.c"
    r2 = IMMEDIATE(65);
    // EBPF_OP_CALL pc=56 dst=r0 src=r0 offset=0 imm=15
#line 164 "sample/bind_policy.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 164 "sample/bind_policy.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 164 "sample/bind_policy.c"
        return 0;
#line 164 "sample/bind_policy.c"
    }
    // EBPF_OP_MOV64_REG pc=57 dst=r2 src=r10 offset=0 imm=0
#line 164 "sample/bind_policy.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=58 dst=r2 src=r0 offset=0 imm=-24
#line 164 "sample/bind_policy.c"
    r2 += IMMEDIATE(-24);
    // EBPF_OP_LDDW pc=59 dst=r1 src=r1 offset=0 imm=1
#line 167 "sample/bind_policy.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_CALL pc=61 dst=r0 src=r0 offset=0 imm=1
#line 167 "sample/bind_policy.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
#line 167 "sample/bind_policy.c"
    if ((runtime_context->helper_data[3].tail_call) && (r0 == 0)) {
#line 167 "sample/bind_policy.c"
        return 0;
#line 167 "sample/bind_policy.c"
    }
    // EBPF_OP_MOV64_REG pc=62 dst=r7 src=r0 offset=0 imm=0
#line 167 "sample/bind_policy.c"
    r7 = r0;
    // EBPF_OP_JEQ_IMM pc=63 dst=r7 src=r0 offset=23 imm=0
#line 168 "sample/bind_policy.c"
    if (r7 == IMMEDIATE(0)) {
#line 168 "sample/bind_policy.c"
        goto label_2;
#line 168 "sample/bind_policy.c"
    }
    // EBPF_OP_MOV64_IMM pc=64 dst=r1 src=r0 offset=0 imm=10
#line 168 "sample/bind_policy.c"
    r1 = IMMEDIATE(10);
    // EBPF_OP_STXH pc=65 dst=r10 src=r1 offset=-56 imm=0
#line 169 "sample/bind_policy.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-56));
    // EBPF_OP_LDDW pc=66 dst=r1 src=r0 offset=0 imm=1869182051
#line 169 "sample/bind_policy.c"
    r1 = (uint64_t)8441220621100741731;
    // EBPF_OP_STXDW pc=68 dst=r10 src=r1 offset=-64 imm=0
#line 169 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-64));
    // EBPF_OP_LDDW pc=69 dst=r1 src=r0 offset=0 imm=1667853423
#line 169 "sample/bind_policy.c"
    r1 = (uint64_t)4692815104753364079;
    // EBPF_OP_STXDW pc=71 dst=r10 src=r1 offset=-72 imm=0
#line 169 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-72));
    // EBPF_OP_LDDW pc=72 dst=r1 src=r0 offset=0 imm=1768038504
#line 169 "sample/bind_policy.c"
    r1 = (uint64_t)8079568156879888488;
    // EBPF_OP_STXDW pc=74 dst=r10 src=r1 offset=-80 imm=0
#line 169 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-80));
    // EBPF_OP_LDDW pc=75 dst=r1 src=r0 offset=0 imm=544498529
#line 169 "sample/bind_policy.c"
    r1 = (uint64_t)7166460028377129825;
    // EBPF_OP_STXDW pc=77 dst=r10 src=r1 offset=-88 imm=0
#line 169 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
    // EBPF_OP_LDDW pc=78 dst=r1 src=r0 offset=0 imm=1853189958
#line 169 "sample/bind_policy.c"
    r1 = (uint64_t)8675375872921136966;
    // EBPF_OP_STXDW pc=80 dst=r10 src=r1 offset=-96 imm=0
#line 169 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
    // EBPF_OP_LDXW pc=81 dst=r3 src=r7 offset=0 imm=0
#line 169 "sample/bind_policy.c"
    READ_ONCE_32(r3, r7, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=82 dst=r1 src=r10 offset=0 imm=0
#line 169 "sample/bind_policy.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=83 dst=r1 src=r0 offset=0 imm=-96
#line 169 "sample/bind_policy.c"
    r1 += IMMEDIATE(-96);
    // EBPF_OP_MOV64_IMM pc=84 dst=r2 src=r0 offset=0 imm=42
#line 169 "sample/bind_policy.c"
    r2 = IMMEDIATE(42);
    // EBPF_OP_CALL pc=85 dst=r0 src=r0 offset=0 imm=13
#line 169 "sample/bind_policy.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 169 "sample/bind_policy.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 169 "sample/bind_policy.c"
        return 0;
#line 169 "sample/bind_policy.c"
    }
    // EBPF_OP_JA pc=86 dst=r0 src=r0 offset=74 imm=0
#line 169 "sample/bind_policy.c"
    goto label_5;
label_2:
    // EBPF_OP_STXDW pc=87 dst=r10 src=r8 offset=-24 imm=0
#line 176 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r8, OFFSET(-24));
    // EBPF_OP_MOV64_REG pc=88 dst=r2 src=r10 offset=0 imm=0
#line 176 "sample/bind_policy.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=89 dst=r2 src=r0 offset=0 imm=-24
#line 176 "sample/bind_policy.c"
    r2 += IMMEDIATE(-24);
    // EBPF_OP_LDDW pc=90 dst=r1 src=r1 offset=0 imm=1
#line 177 "sample/bind_policy.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_CALL pc=92 dst=r0 src=r0 offset=0 imm=1
#line 177 "sample/bind_policy.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
#line 177 "sample/bind_policy.c"
    if ((runtime_context->helper_data[3].tail_call) && (r0 == 0)) {
#line 177 "sample/bind_policy.c"
        return 0;
#line 177 "sample/bind_policy.c"
    }
    // EBPF_OP_MOV64_REG pc=93 dst=r7 src=r0 offset=0 imm=0
#line 177 "sample/bind_policy.c"
    r7 = r0;
    // EBPF_OP_JEQ_IMM pc=94 dst=r7 src=r0 offset=23 imm=0
#line 178 "sample/bind_policy.c"
    if (r7 == IMMEDIATE(0)) {
#line 178 "sample/bind_policy.c"
        goto label_3;
#line 178 "sample/bind_policy.c"
    }
    // EBPF_OP_MOV64_IMM pc=95 dst=r1 src=r0 offset=0 imm=0
#line 178 "sample/bind_policy.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=96 dst=r10 src=r1 offset=-56 imm=0
#line 179 "sample/bind_policy.c"
    WRITE_ONCE_8(r10, (uint8_t)r1, OFFSET(-56));
    // EBPF_OP_LDDW pc=97 dst=r1 src=r0 offset=0 imm=1852795252
#line 179 "sample/bind_policy.c"
    r1 = (uint64_t)753549458430454132;
    // EBPF_OP_STXDW pc=99 dst=r10 src=r1 offset=-64 imm=0
#line 179 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-64));
    // EBPF_OP_LDDW pc=100 dst=r1 src=r0 offset=0 imm=2036558188
#line 179 "sample/bind_policy.c"
    r1 = (uint64_t)7152033118757808492;
    // EBPF_OP_STXDW pc=102 dst=r10 src=r1 offset=-72 imm=0
#line 179 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-72));
    // EBPF_OP_LDDW pc=103 dst=r1 src=r0 offset=0 imm=1852400160
#line 179 "sample/bind_policy.c"
    r1 = (uint64_t)8029953751322812960;
    // EBPF_OP_STXDW pc=105 dst=r10 src=r1 offset=-80 imm=0
#line 179 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-80));
    // EBPF_OP_LDDW pc=106 dst=r1 src=r0 offset=0 imm=1647146098
#line 179 "sample/bind_policy.c"
    r1 = (uint64_t)7234315238536737906;
    // EBPF_OP_STXDW pc=108 dst=r10 src=r1 offset=-88 imm=0
#line 179 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
    // EBPF_OP_LDDW pc=109 dst=r1 src=r0 offset=0 imm=1853189958
#line 179 "sample/bind_policy.c"
    r1 = (uint64_t)8029953751323602758;
    // EBPF_OP_STXDW pc=111 dst=r10 src=r1 offset=-96 imm=0
#line 179 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
    // EBPF_OP_LDXW pc=112 dst=r3 src=r7 offset=0 imm=0
#line 179 "sample/bind_policy.c"
    READ_ONCE_32(r3, r7, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=113 dst=r1 src=r10 offset=0 imm=0
#line 179 "sample/bind_policy.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=114 dst=r1 src=r0 offset=0 imm=-96
#line 179 "sample/bind_policy.c"
    r1 += IMMEDIATE(-96);
    // EBPF_OP_MOV64_IMM pc=115 dst=r2 src=r0 offset=0 imm=41
#line 179 "sample/bind_policy.c"
    r2 = IMMEDIATE(41);
    // EBPF_OP_CALL pc=116 dst=r0 src=r0 offset=0 imm=13
#line 179 "sample/bind_policy.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 179 "sample/bind_policy.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 179 "sample/bind_policy.c"
        return 0;
#line 179 "sample/bind_policy.c"
    }
    // EBPF_OP_JA pc=117 dst=r0 src=r0 offset=43 imm=0
#line 179 "sample/bind_policy.c"
    goto label_5;
label_3:
    // EBPF_OP_LDXDW pc=118 dst=r1 src=r6 offset=16 imm=0
#line 186 "sample/bind_policy.c"
    READ_ONCE_64(r1, r6, OFFSET(16));
    // EBPF_OP_STXB pc=119 dst=r10 src=r8 offset=-14 imm=0
#line 188 "sample/bind_policy.c"
    WRITE_ONCE_8(r10, (uint8_t)r8, OFFSET(-14));
    // EBPF_OP_STXH pc=120 dst=r10 src=r8 offset=-16 imm=0
#line 187 "sample/bind_policy.c"
    WRITE_ONCE_16(r10, (uint16_t)r8, OFFSET(-16));
    // EBPF_OP_STXDW pc=121 dst=r10 src=r1 offset=-24 imm=0
#line 186 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-24));
    // EBPF_OP_MOV64_REG pc=122 dst=r2 src=r10 offset=0 imm=0
#line 186 "sample/bind_policy.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=123 dst=r2 src=r0 offset=0 imm=-24
#line 186 "sample/bind_policy.c"
    r2 += IMMEDIATE(-24);
    // EBPF_OP_LDDW pc=124 dst=r1 src=r1 offset=0 imm=1
#line 189 "sample/bind_policy.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_CALL pc=126 dst=r0 src=r0 offset=0 imm=1
#line 189 "sample/bind_policy.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
#line 189 "sample/bind_policy.c"
    if ((runtime_context->helper_data[3].tail_call) && (r0 == 0)) {
#line 189 "sample/bind_policy.c"
        return 0;
#line 189 "sample/bind_policy.c"
    }
    // EBPF_OP_MOV64_REG pc=127 dst=r7 src=r0 offset=0 imm=0
#line 189 "sample/bind_policy.c"
    r7 = r0;
    // EBPF_OP_JEQ_IMM pc=128 dst=r7 src=r0 offset=23 imm=0
#line 190 "sample/bind_policy.c"
    if (r7 == IMMEDIATE(0)) {
#line 190 "sample/bind_policy.c"
        goto label_4;
#line 190 "sample/bind_policy.c"
    }
    // EBPF_OP_MOV64_IMM pc=129 dst=r1 src=r0 offset=0 imm=685349
#line 190 "sample/bind_policy.c"
    r1 = IMMEDIATE(685349);
    // EBPF_OP_STXW pc=130 dst=r10 src=r1 offset=-56 imm=0
#line 191 "sample/bind_policy.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-56));
    // EBPF_OP_LDDW pc=131 dst=r1 src=r0 offset=0 imm=1952661792
#line 191 "sample/bind_policy.c"
    r1 = (uint64_t)4426597982466687264;
    // EBPF_OP_STXDW pc=133 dst=r10 src=r1 offset=-64 imm=0
#line 191 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-64));
    // EBPF_OP_LDDW pc=134 dst=r1 src=r0 offset=0 imm=1819242528
#line 191 "sample/bind_policy.c"
    r1 = (uint64_t)4213508230823768096;
    // EBPF_OP_STXDW pc=136 dst=r10 src=r1 offset=-72 imm=0
#line 191 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-72));
    // EBPF_OP_LDDW pc=137 dst=r1 src=r0 offset=0 imm=543450483
#line 191 "sample/bind_policy.c"
    r1 = (uint64_t)7236837521402127731;
    // EBPF_OP_STXDW pc=139 dst=r10 src=r1 offset=-80 imm=0
#line 191 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-80));
    // EBPF_OP_LDDW pc=140 dst=r1 src=r0 offset=0 imm=1936024431
#line 191 "sample/bind_policy.c"
    r1 = (uint64_t)7017221143277167471;
    // EBPF_OP_STXDW pc=142 dst=r10 src=r1 offset=-88 imm=0
#line 191 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
    // EBPF_OP_LDDW pc=143 dst=r1 src=r0 offset=0 imm=1853189958
#line 191 "sample/bind_policy.c"
    r1 = (uint64_t)8246126533437386566;
    // EBPF_OP_STXDW pc=145 dst=r10 src=r1 offset=-96 imm=0
#line 191 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
    // EBPF_OP_LDXW pc=146 dst=r3 src=r7 offset=0 imm=0
#line 191 "sample/bind_policy.c"
    READ_ONCE_32(r3, r7, OFFSET(0));
    // EBPF_OP_MOV64_REG pc=147 dst=r1 src=r10 offset=0 imm=0
#line 191 "sample/bind_policy.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=148 dst=r1 src=r0 offset=0 imm=-96
#line 191 "sample/bind_policy.c"
    r1 += IMMEDIATE(-96);
    // EBPF_OP_MOV64_IMM pc=149 dst=r2 src=r0 offset=0 imm=44
#line 191 "sample/bind_policy.c"
    r2 = IMMEDIATE(44);
    // EBPF_OP_CALL pc=150 dst=r0 src=r0 offset=0 imm=13
#line 191 "sample/bind_policy.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 191 "sample/bind_policy.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 191 "sample/bind_policy.c"
        return 0;
#line 191 "sample/bind_policy.c"
    }
    // EBPF_OP_JA pc=151 dst=r0 src=r0 offset=9 imm=0
#line 191 "sample/bind_policy.c"
    goto label_5;
label_4:
    // EBPF_OP_STXDW pc=152 dst=r10 src=r8 offset=-24 imm=0
#line 198 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r8, OFFSET(-24));
    // EBPF_OP_MOV64_REG pc=153 dst=r2 src=r10 offset=0 imm=0
#line 198 "sample/bind_policy.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=154 dst=r2 src=r0 offset=0 imm=-24
#line 198 "sample/bind_policy.c"
    r2 += IMMEDIATE(-24);
    // EBPF_OP_LDDW pc=155 dst=r1 src=r1 offset=0 imm=1
#line 199 "sample/bind_policy.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_CALL pc=157 dst=r0 src=r0 offset=0 imm=1
#line 199 "sample/bind_policy.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
#line 199 "sample/bind_policy.c"
    if ((runtime_context->helper_data[3].tail_call) && (r0 == 0)) {
#line 199 "sample/bind_policy.c"
        return 0;
#line 199 "sample/bind_policy.c"
    }
    // EBPF_OP_MOV64_REG pc=158 dst=r7 src=r0 offset=0 imm=0
#line 199 "sample/bind_policy.c"
    r7 = r0;
    // EBPF_OP_MOV64_IMM pc=159 dst=r8 src=r0 offset=0 imm=1
#line 199 "sample/bind_policy.c"
    r8 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=160 dst=r7 src=r0 offset=1 imm=0
#line 200 "sample/bind_policy.c"
    if (r7 == IMMEDIATE(0)) {
#line 200 "sample/bind_policy.c"
        goto label_6;
#line 200 "sample/bind_policy.c"
    }
label_5:
    // EBPF_OP_LDXW pc=161 dst=r8 src=r7 offset=0 imm=0
#line 200 "sample/bind_policy.c"
    READ_ONCE_32(r8, r7, OFFSET(0));
label_6:
    // EBPF_OP_CALL pc=162 dst=r0 src=r0 offset=0 imm=9
#line 121 "sample/bind_policy.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 121 "sample/bind_policy.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 121 "sample/bind_policy.c"
        return 0;
#line 121 "sample/bind_policy.c"
    }
    // EBPF_OP_STXDW pc=163 dst=r10 src=r0 offset=-96 imm=0
#line 121 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r0, OFFSET(-96));
    // EBPF_OP_MOV64_IMM pc=164 dst=r1 src=r0 offset=0 imm=0
#line 121 "sample/bind_policy.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXDW pc=165 dst=r10 src=r1 offset=-8 imm=0
#line 122 "sample/bind_policy.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-8));
    // EBPF_OP_LDXH pc=166 dst=r1 src=r6 offset=26 imm=0
#line 125 "sample/bind_policy.c"
    READ_ONCE_16(r1, r6, OFFSET(26));
    // EBPF_OP_STXW pc=167 dst=r10 src=r8 offset=-4 imm=0
#line 126 "sample/bind_policy.c"
    WRITE_ONCE_32(r10, (uint32_t)r8, OFFSET(-4));
    // EBPF_OP_STXH pc=168 dst=r10 src=r1 offset=-8 imm=0
#line 125 "sample/bind_policy.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-8));
    // EBPF_OP_MOV64_REG pc=169 dst=r2 src=r10 offset=0 imm=0
#line 125 "sample/bind_policy.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=170 dst=r2 src=r0 offset=0 imm=-96
#line 125 "sample/bind_policy.c"
    r2 += IMMEDIATE(-96);
    // EBPF_OP_MOV64_REG pc=171 dst=r3 src=r10 offset=0 imm=0
#line 125 "sample/bind_policy.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=172 dst=r3 src=r0 offset=0 imm=-8
#line 125 "sample/bind_policy.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=173 dst=r1 src=r1 offset=0 imm=2
#line 129 "sample/bind_policy.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_MOV64_IMM pc=175 dst=r4 src=r0 offset=0 imm=0
#line 129 "sample/bind_policy.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=176 dst=r0 src=r0 offset=0 imm=2
#line 129 "sample/bind_policy.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 129 "sample/bind_policy.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 129 "sample/bind_policy.c"
        return 0;
#line 129 "sample/bind_policy.c"
    }
label_7:
    // EBPF_OP_MOV64_REG pc=177 dst=r0 src=r8 offset=0 imm=0
#line 236 "sample/bind_policy.c"
    r0 = r8;
    // EBPF_OP_EXIT pc=178 dst=r0 src=r0 offset=0 imm=0
#line 236 "sample/bind_policy.c"
    return r0;
#line 226 "sample/bind_policy.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        {1, 144, 144}, // Version header.
        authorize_bind,
        "bind",
        "bind",
        "authorize_bind",
        authorize_bind_maps,
        2,
        authorize_bind_helpers,
        5,
        179,
        &authorize_bind_program_type_guid,
        &authorize_bind_attach_type_guid,
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
    version->minor = 1;
    version->revision = 0;
}

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = NULL;
    *count = 0;
}

metadata_table_t bind_policy_metadata_table = {
    sizeof(metadata_table_t),
    _get_programs,
    _get_maps,
    _get_hash,
    _get_version,
    _get_map_initial_values,
    _get_global_variable_sections,
};
