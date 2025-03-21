// Copyright (c) eBPF for Windows contributors
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
         4,                 // Size in bytes of a map value.
         10,                // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         LIBBPF_PIN_NONE,   // Pinning type for the map.
         0,                 // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "HASH_map"},
    {
     {0, 0},
     {
         1,                        // Current Version.
         80,                       // Struct size up to the last field.
         80,                       // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_PERCPU_HASH, // Type of map.
         4,                        // Size in bytes of a map key.
         4,                        // Size in bytes of a map value.
         10,                       // Maximum number of entries allowed in the map.
         0,                        // Inner map index.
         LIBBPF_PIN_NONE,          // Pinning type for the map.
         0,                        // Identifier for a map template.
         0,                        // The id of the inner map template.
     },
     "PERCPU_HASH_map"},
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
         10,                 // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         LIBBPF_PIN_NONE,    // Pinning type for the map.
         0,                  // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "ARRAY_map"},
    {
     {0, 0},
     {
         1,                         // Current Version.
         80,                        // Struct size up to the last field.
         80,                        // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_PERCPU_ARRAY, // Type of map.
         4,                         // Size in bytes of a map key.
         4,                         // Size in bytes of a map value.
         10,                        // Maximum number of entries allowed in the map.
         0,                         // Inner map index.
         LIBBPF_PIN_NONE,           // Pinning type for the map.
         0,                         // Identifier for a map template.
         0,                         // The id of the inner map template.
     },
     "PERCPU_ARRAY_map"},
    {
     {0, 0},
     {
         1,                     // Current Version.
         80,                    // Struct size up to the last field.
         80,                    // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_LRU_HASH, // Type of map.
         4,                     // Size in bytes of a map key.
         4,                     // Size in bytes of a map value.
         10,                    // Maximum number of entries allowed in the map.
         0,                     // Inner map index.
         LIBBPF_PIN_NONE,       // Pinning type for the map.
         0,                     // Identifier for a map template.
         0,                     // The id of the inner map template.
     },
     "LRU_HASH_map"},
    {
     {0, 0},
     {
         1,                            // Current Version.
         80,                           // Struct size up to the last field.
         80,                           // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_LRU_PERCPU_HASH, // Type of map.
         4,                            // Size in bytes of a map key.
         4,                            // Size in bytes of a map value.
         10,                           // Maximum number of entries allowed in the map.
         0,                            // Inner map index.
         LIBBPF_PIN_NONE,              // Pinning type for the map.
         0,                            // Identifier for a map template.
         0,                            // The id of the inner map template.
     },
     "LRU_PERCPU_HASH_map"},
    {
     {0, 0},
     {
         1,                  // Current Version.
         80,                 // Struct size up to the last field.
         80,                 // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_QUEUE, // Type of map.
         0,                  // Size in bytes of a map key.
         4,                  // Size in bytes of a map value.
         10,                 // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         LIBBPF_PIN_NONE,    // Pinning type for the map.
         0,                  // Identifier for a map template.
         0,                  // The id of the inner map template.
     },
     "QUEUE_map"},
    {
     {0, 0},
     {
         1,                  // Current Version.
         80,                 // Struct size up to the last field.
         80,                 // Total struct size including padding.
     },
     {
         BPF_MAP_TYPE_STACK, // Type of map.
         0,                  // Size in bytes of a map key.
         4,                  // Size in bytes of a map value.
         10,                 // Maximum number of entries allowed in the map.
         0,                  // Inner map index.
         LIBBPF_PIN_NONE,    // Pinning type for the map.
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

static void
_get_global_variable_sections(
    _Outptr_result_buffer_maybenull_(*count) global_variable_section_info_t** global_variable_sections,
    _Out_ size_t* count)
{
    *global_variable_sections = NULL;
    *count = 0;
}

static helper_function_entry_t test_maps_helpers[] = {
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
    {
     {1, 40, 40}, // Version header.
     12,
     "helper_id_12",
    },
    {
     {1, 40, 40}, // Version header.
     3,
     "helper_id_3",
    },
    {
     {1, 40, 40}, // Version header.
     13,
     "helper_id_13",
    },
    {
     {1, 40, 40}, // Version header.
     4,
     "helper_id_4",
    },
    {
     {1, 40, 40}, // Version header.
     18,
     "helper_id_18",
    },
    {
     {1, 40, 40}, // Version header.
     14,
     "helper_id_14",
    },
    {
     {1, 40, 40}, // Version header.
     17,
     "helper_id_17",
    },
    {
     {1, 40, 40}, // Version header.
     16,
     "helper_id_16",
    },
    {
     {1, 40, 40}, // Version header.
     15,
     "helper_id_15",
    },
};

static GUID test_maps_program_type_guid = {
    0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
static GUID test_maps_attach_type_guid = {0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};
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

#pragma code_seg(push, "sample~1")
static uint64_t
test_maps(void* context, const program_runtime_context_t* runtime_context)
#line 290 "sample/undocked/map.c"
{
#line 290 "sample/undocked/map.c"
    // Prologue.
#line 290 "sample/undocked/map.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 290 "sample/undocked/map.c"
    register uint64_t r0 = 0;
#line 290 "sample/undocked/map.c"
    register uint64_t r1 = 0;
#line 290 "sample/undocked/map.c"
    register uint64_t r2 = 0;
#line 290 "sample/undocked/map.c"
    register uint64_t r3 = 0;
#line 290 "sample/undocked/map.c"
    register uint64_t r4 = 0;
#line 290 "sample/undocked/map.c"
    register uint64_t r5 = 0;
#line 290 "sample/undocked/map.c"
    register uint64_t r6 = 0;
#line 290 "sample/undocked/map.c"
    register uint64_t r7 = 0;
#line 290 "sample/undocked/map.c"
    register uint64_t r8 = 0;
#line 290 "sample/undocked/map.c"
    register uint64_t r10 = 0;

#line 290 "sample/undocked/map.c"
    r1 = (uintptr_t)context;
#line 290 "sample/undocked/map.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_MOV64_IMM pc=0 dst=r1 src=r0 offset=0 imm=0
#line 290 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1 dst=r10 src=r1 offset=-4 imm=0
#line 70 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_IMM pc=2 dst=r1 src=r0 offset=0 imm=1
#line 70 "sample/undocked/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=3 dst=r10 src=r1 offset=-8 imm=0
#line 71 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=4 dst=r2 src=r10 offset=0 imm=0
#line 71 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=5 dst=r2 src=r0 offset=0 imm=-4
#line 71 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=6 dst=r3 src=r10 offset=0 imm=0
#line 71 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=7 dst=r3 src=r0 offset=0 imm=-8
#line 71 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=8 dst=r1 src=r1 offset=0 imm=1
#line 74 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=10 dst=r4 src=r0 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=11 dst=r0 src=r0 offset=0 imm=2
#line 74 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 74 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 74 "sample/undocked/map.c"
        return 0;
#line 74 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=12 dst=r6 src=r0 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=13 dst=r3 src=r6 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=14 dst=r3 src=r0 offset=0 imm=32
#line 74 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=15 dst=r3 src=r0 offset=0 imm=32
#line 74 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=16 dst=r3 src=r0 offset=9 imm=-1
#line 75 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 75 "sample/undocked/map.c"
        goto label_2;
#line 75 "sample/undocked/map.c"
    }
label_1:
    // EBPF_OP_LDDW pc=17 dst=r1 src=r0 offset=0 imm=1684369010
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=19 dst=r10 src=r1 offset=-88 imm=0
#line 75 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=20 dst=r1 src=r0 offset=0 imm=544040300
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=22 dst=r10 src=r1 offset=-96 imm=0
#line 75 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=23 dst=r1 src=r0 offset=0 imm=1633972341
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671142817909;
    // EBPF_OP_JA pc=25 dst=r0 src=r0 offset=45 imm=0
#line 75 "sample/undocked/map.c"
    goto label_5;
label_2:
    // EBPF_OP_MOV64_REG pc=26 dst=r2 src=r10 offset=0 imm=0
#line 75 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=27 dst=r2 src=r0 offset=0 imm=-4
#line 80 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=28 dst=r1 src=r1 offset=0 imm=1
#line 80 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_CALL pc=30 dst=r0 src=r0 offset=0 imm=1
#line 80 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 80 "sample/undocked/map.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 80 "sample/undocked/map.c"
        return 0;
#line 80 "sample/undocked/map.c"
    }
    // EBPF_OP_JNE_IMM pc=31 dst=r0 src=r0 offset=21 imm=0
#line 81 "sample/undocked/map.c"
    if (r0 != IMMEDIATE(0)) {
#line 81 "sample/undocked/map.c"
        goto label_4;
#line 81 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_IMM pc=32 dst=r1 src=r0 offset=0 imm=76
#line 81 "sample/undocked/map.c"
    r1 = IMMEDIATE(76);
    // EBPF_OP_STXH pc=33 dst=r10 src=r1 offset=-80 imm=0
#line 82 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=34 dst=r1 src=r0 offset=0 imm=1684369010
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)5500388420933217906;
    // EBPF_OP_STXDW pc=36 dst=r10 src=r1 offset=-88 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=37 dst=r1 src=r0 offset=0 imm=544040300
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=39 dst=r10 src=r1 offset=-96 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=40 dst=r1 src=r0 offset=0 imm=1802465132
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)7304680770234183532;
    // EBPF_OP_STXDW pc=42 dst=r10 src=r1 offset=-104 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=43 dst=r1 src=r0 offset=0 imm=1600548962
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=45 dst=r10 src=r1 offset=-112 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=46 dst=r1 src=r10 offset=0 imm=0
#line 82 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=47 dst=r1 src=r0 offset=0 imm=-112
#line 82 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=48 dst=r2 src=r0 offset=0 imm=34
#line 82 "sample/undocked/map.c"
    r2 = IMMEDIATE(34);
label_3:
    // EBPF_OP_CALL pc=49 dst=r0 src=r0 offset=0 imm=12
#line 82 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 82 "sample/undocked/map.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 82 "sample/undocked/map.c"
        return 0;
#line 82 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=50 dst=r6 src=r0 offset=0 imm=-1
#line 82 "sample/undocked/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JA pc=52 dst=r0 src=r0 offset=26 imm=0
#line 82 "sample/undocked/map.c"
    goto label_6;
label_4:
    // EBPF_OP_MOV64_REG pc=53 dst=r2 src=r10 offset=0 imm=0
#line 82 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=54 dst=r2 src=r0 offset=0 imm=-4
#line 86 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=55 dst=r1 src=r1 offset=0 imm=1
#line 86 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_CALL pc=57 dst=r0 src=r0 offset=0 imm=3
#line 86 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
#line 86 "sample/undocked/map.c"
    if ((runtime_context->helper_data[3].tail_call) && (r0 == 0)) {
#line 86 "sample/undocked/map.c"
        return 0;
#line 86 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=58 dst=r6 src=r0 offset=0 imm=0
#line 86 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=59 dst=r3 src=r6 offset=0 imm=0
#line 86 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=60 dst=r3 src=r0 offset=0 imm=32
#line 86 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=61 dst=r3 src=r0 offset=0 imm=32
#line 86 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=62 dst=r3 src=r0 offset=41 imm=-1
#line 87 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 87 "sample/undocked/map.c"
        goto label_10;
#line 87 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=63 dst=r1 src=r0 offset=0 imm=1684369010
#line 87 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=65 dst=r10 src=r1 offset=-88 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=66 dst=r1 src=r0 offset=0 imm=544040300
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=68 dst=r10 src=r1 offset=-96 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=69 dst=r1 src=r0 offset=0 imm=1701602660
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671210448228;
label_5:
    // EBPF_OP_STXDW pc=71 dst=r10 src=r1 offset=-104 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=72 dst=r1 src=r0 offset=0 imm=1600548962
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=74 dst=r10 src=r1 offset=-112 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=75 dst=r1 src=r10 offset=0 imm=0
#line 88 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=76 dst=r1 src=r0 offset=0 imm=-112
#line 88 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=77 dst=r2 src=r0 offset=0 imm=32
#line 88 "sample/undocked/map.c"
    r2 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=78 dst=r0 src=r0 offset=0 imm=13
#line 88 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 88 "sample/undocked/map.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 88 "sample/undocked/map.c"
        return 0;
#line 88 "sample/undocked/map.c"
    }
label_6:
    // EBPF_OP_MOV64_IMM pc=79 dst=r1 src=r0 offset=0 imm=100
#line 88 "sample/undocked/map.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXH pc=80 dst=r10 src=r1 offset=-76 imm=0
#line 293 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-76)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=81 dst=r1 src=r0 offset=0 imm=622879845
#line 293 "sample/undocked/map.c"
    r1 = IMMEDIATE(622879845);
    // EBPF_OP_STXW pc=82 dst=r10 src=r1 offset=-80 imm=0
#line 293 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=83 dst=r1 src=r0 offset=0 imm=1701978184
#line 293 "sample/undocked/map.c"
    r1 = (uint64_t)7958552634295722056;
    // EBPF_OP_STXDW pc=85 dst=r10 src=r1 offset=-88 imm=0
#line 293 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=86 dst=r1 src=r0 offset=0 imm=1885433120
#line 293 "sample/undocked/map.c"
    r1 = (uint64_t)5999155482795797792;
    // EBPF_OP_STXDW pc=88 dst=r10 src=r1 offset=-96 imm=0
#line 293 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=89 dst=r1 src=r0 offset=0 imm=1279349317
#line 293 "sample/undocked/map.c"
    r1 = (uint64_t)8245921731643003461;
    // EBPF_OP_STXDW pc=91 dst=r10 src=r1 offset=-104 imm=0
#line 293 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=92 dst=r1 src=r0 offset=0 imm=1953719636
#line 293 "sample/undocked/map.c"
    r1 = (uint64_t)5639992313069659476;
label_7:
    // EBPF_OP_STXDW pc=94 dst=r10 src=r1 offset=-112 imm=0
#line 293 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=95 dst=r3 src=r6 offset=0 imm=0
#line 293 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=96 dst=r3 src=r0 offset=0 imm=32
#line 293 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=97 dst=r3 src=r0 offset=0 imm=32
#line 293 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=98 dst=r1 src=r10 offset=0 imm=0
#line 293 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=99 dst=r1 src=r0 offset=0 imm=-112
#line 293 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=100 dst=r2 src=r0 offset=0 imm=38
#line 293 "sample/undocked/map.c"
    r2 = IMMEDIATE(38);
label_8:
    // EBPF_OP_CALL pc=101 dst=r0 src=r0 offset=0 imm=13
#line 293 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 293 "sample/undocked/map.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 293 "sample/undocked/map.c"
        return 0;
#line 293 "sample/undocked/map.c"
    }
label_9:
    // EBPF_OP_MOV64_REG pc=102 dst=r0 src=r6 offset=0 imm=0
#line 306 "sample/undocked/map.c"
    r0 = r6;
    // EBPF_OP_EXIT pc=103 dst=r0 src=r0 offset=0 imm=0
#line 306 "sample/undocked/map.c"
    return r0;
label_10:
    // EBPF_OP_MOV64_REG pc=104 dst=r2 src=r10 offset=0 imm=0
#line 306 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=105 dst=r2 src=r0 offset=0 imm=-4
#line 92 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=106 dst=r3 src=r10 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=107 dst=r3 src=r0 offset=0 imm=-8
#line 92 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=108 dst=r1 src=r1 offset=0 imm=1
#line 92 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_MOV64_IMM pc=110 dst=r4 src=r0 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=111 dst=r0 src=r0 offset=0 imm=2
#line 92 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 92 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 92 "sample/undocked/map.c"
        return 0;
#line 92 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=112 dst=r6 src=r0 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=113 dst=r3 src=r6 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=114 dst=r3 src=r0 offset=0 imm=32
#line 92 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=115 dst=r3 src=r0 offset=0 imm=32
#line 92 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=116 dst=r3 src=r0 offset=1 imm=-1
#line 93 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 93 "sample/undocked/map.c"
        goto label_11;
#line 93 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=117 dst=r0 src=r0 offset=-101 imm=0
#line 93 "sample/undocked/map.c"
    goto label_1;
label_11:
    // EBPF_OP_MOV64_REG pc=118 dst=r2 src=r10 offset=0 imm=0
#line 93 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=119 dst=r2 src=r0 offset=0 imm=-4
#line 103 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=120 dst=r1 src=r1 offset=0 imm=1
#line 103 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[0].address);
    // EBPF_OP_CALL pc=122 dst=r0 src=r0 offset=0 imm=4
#line 103 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[5].address(r1, r2, r3, r4, r5, context);
#line 103 "sample/undocked/map.c"
    if ((runtime_context->helper_data[5].tail_call) && (r0 == 0)) {
#line 103 "sample/undocked/map.c"
        return 0;
#line 103 "sample/undocked/map.c"
    }
    // EBPF_OP_JNE_IMM pc=123 dst=r0 src=r0 offset=23 imm=0
#line 104 "sample/undocked/map.c"
    if (r0 != IMMEDIATE(0)) {
#line 104 "sample/undocked/map.c"
        goto label_12;
#line 104 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_IMM pc=124 dst=r1 src=r0 offset=0 imm=0
#line 104 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=125 dst=r10 src=r1 offset=-68 imm=0
#line 105 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-68)) = (uint8_t)r1;
    // EBPF_OP_MOV64_IMM pc=126 dst=r1 src=r0 offset=0 imm=1280070990
#line 105 "sample/undocked/map.c"
    r1 = IMMEDIATE(1280070990);
    // EBPF_OP_STXW pc=127 dst=r10 src=r1 offset=-72 imm=0
#line 105 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=128 dst=r1 src=r0 offset=0 imm=1920300133
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)2334102031925867621;
    // EBPF_OP_STXDW pc=130 dst=r10 src=r1 offset=-80 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=131 dst=r1 src=r0 offset=0 imm=1818582885
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)8223693201956233061;
    // EBPF_OP_STXDW pc=133 dst=r10 src=r1 offset=-88 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=134 dst=r1 src=r0 offset=0 imm=1683973230
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)8387229063778886766;
    // EBPF_OP_STXDW pc=136 dst=r10 src=r1 offset=-96 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=137 dst=r1 src=r0 offset=0 imm=1802465132
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)7016450394082471788;
    // EBPF_OP_STXDW pc=139 dst=r10 src=r1 offset=-104 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=140 dst=r1 src=r0 offset=0 imm=1600548962
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=142 dst=r10 src=r1 offset=-112 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=143 dst=r1 src=r10 offset=0 imm=0
#line 105 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=144 dst=r1 src=r0 offset=0 imm=-112
#line 105 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=145 dst=r2 src=r0 offset=0 imm=45
#line 105 "sample/undocked/map.c"
    r2 = IMMEDIATE(45);
    // EBPF_OP_JA pc=146 dst=r0 src=r0 offset=-98 imm=0
#line 105 "sample/undocked/map.c"
    goto label_3;
label_12:
    // EBPF_OP_MOV64_IMM pc=147 dst=r1 src=r0 offset=0 imm=0
#line 105 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=148 dst=r10 src=r1 offset=-4 imm=0
#line 70 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_IMM pc=149 dst=r1 src=r0 offset=0 imm=1
#line 70 "sample/undocked/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=150 dst=r10 src=r1 offset=-8 imm=0
#line 71 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=151 dst=r2 src=r10 offset=0 imm=0
#line 71 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=152 dst=r2 src=r0 offset=0 imm=-4
#line 71 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=153 dst=r3 src=r10 offset=0 imm=0
#line 71 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=154 dst=r3 src=r0 offset=0 imm=-8
#line 71 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=155 dst=r1 src=r1 offset=0 imm=2
#line 74 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_MOV64_IMM pc=157 dst=r4 src=r0 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=158 dst=r0 src=r0 offset=0 imm=2
#line 74 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 74 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 74 "sample/undocked/map.c"
        return 0;
#line 74 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=159 dst=r6 src=r0 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=160 dst=r3 src=r6 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=161 dst=r3 src=r0 offset=0 imm=32
#line 74 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=162 dst=r3 src=r0 offset=0 imm=32
#line 74 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=163 dst=r3 src=r0 offset=9 imm=-1
#line 75 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 75 "sample/undocked/map.c"
        goto label_14;
#line 75 "sample/undocked/map.c"
    }
label_13:
    // EBPF_OP_LDDW pc=164 dst=r1 src=r0 offset=0 imm=1684369010
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=166 dst=r10 src=r1 offset=-88 imm=0
#line 75 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=167 dst=r1 src=r0 offset=0 imm=544040300
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=169 dst=r10 src=r1 offset=-96 imm=0
#line 75 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=170 dst=r1 src=r0 offset=0 imm=1633972341
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671142817909;
    // EBPF_OP_JA pc=172 dst=r0 src=r0 offset=45 imm=0
#line 75 "sample/undocked/map.c"
    goto label_17;
label_14:
    // EBPF_OP_MOV64_REG pc=173 dst=r2 src=r10 offset=0 imm=0
#line 75 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=174 dst=r2 src=r0 offset=0 imm=-4
#line 80 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=175 dst=r1 src=r1 offset=0 imm=2
#line 80 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=177 dst=r0 src=r0 offset=0 imm=1
#line 80 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 80 "sample/undocked/map.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 80 "sample/undocked/map.c"
        return 0;
#line 80 "sample/undocked/map.c"
    }
    // EBPF_OP_JNE_IMM pc=178 dst=r0 src=r0 offset=21 imm=0
#line 81 "sample/undocked/map.c"
    if (r0 != IMMEDIATE(0)) {
#line 81 "sample/undocked/map.c"
        goto label_16;
#line 81 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_IMM pc=179 dst=r1 src=r0 offset=0 imm=76
#line 81 "sample/undocked/map.c"
    r1 = IMMEDIATE(76);
    // EBPF_OP_STXH pc=180 dst=r10 src=r1 offset=-80 imm=0
#line 82 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=181 dst=r1 src=r0 offset=0 imm=1684369010
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)5500388420933217906;
    // EBPF_OP_STXDW pc=183 dst=r10 src=r1 offset=-88 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=184 dst=r1 src=r0 offset=0 imm=544040300
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=186 dst=r10 src=r1 offset=-96 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=187 dst=r1 src=r0 offset=0 imm=1802465132
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)7304680770234183532;
    // EBPF_OP_STXDW pc=189 dst=r10 src=r1 offset=-104 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=190 dst=r1 src=r0 offset=0 imm=1600548962
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=192 dst=r10 src=r1 offset=-112 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=193 dst=r1 src=r10 offset=0 imm=0
#line 82 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=194 dst=r1 src=r0 offset=0 imm=-112
#line 82 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=195 dst=r2 src=r0 offset=0 imm=34
#line 82 "sample/undocked/map.c"
    r2 = IMMEDIATE(34);
label_15:
    // EBPF_OP_CALL pc=196 dst=r0 src=r0 offset=0 imm=12
#line 82 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 82 "sample/undocked/map.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 82 "sample/undocked/map.c"
        return 0;
#line 82 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=197 dst=r6 src=r0 offset=0 imm=-1
#line 82 "sample/undocked/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JA pc=199 dst=r0 src=r0 offset=26 imm=0
#line 82 "sample/undocked/map.c"
    goto label_18;
label_16:
    // EBPF_OP_MOV64_REG pc=200 dst=r2 src=r10 offset=0 imm=0
#line 82 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=201 dst=r2 src=r0 offset=0 imm=-4
#line 86 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=202 dst=r1 src=r1 offset=0 imm=2
#line 86 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=204 dst=r0 src=r0 offset=0 imm=3
#line 86 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
#line 86 "sample/undocked/map.c"
    if ((runtime_context->helper_data[3].tail_call) && (r0 == 0)) {
#line 86 "sample/undocked/map.c"
        return 0;
#line 86 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=205 dst=r6 src=r0 offset=0 imm=0
#line 86 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=206 dst=r3 src=r6 offset=0 imm=0
#line 86 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=207 dst=r3 src=r0 offset=0 imm=32
#line 86 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=208 dst=r3 src=r0 offset=0 imm=32
#line 86 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=209 dst=r3 src=r0 offset=42 imm=-1
#line 87 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 87 "sample/undocked/map.c"
        goto label_20;
#line 87 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=210 dst=r1 src=r0 offset=0 imm=1684369010
#line 87 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=212 dst=r10 src=r1 offset=-88 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=213 dst=r1 src=r0 offset=0 imm=544040300
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=215 dst=r10 src=r1 offset=-96 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=216 dst=r1 src=r0 offset=0 imm=1701602660
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671210448228;
label_17:
    // EBPF_OP_STXDW pc=218 dst=r10 src=r1 offset=-104 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=219 dst=r1 src=r0 offset=0 imm=1600548962
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=221 dst=r10 src=r1 offset=-112 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=222 dst=r1 src=r10 offset=0 imm=0
#line 88 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=223 dst=r1 src=r0 offset=0 imm=-112
#line 88 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=224 dst=r2 src=r0 offset=0 imm=32
#line 88 "sample/undocked/map.c"
    r2 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=225 dst=r0 src=r0 offset=0 imm=13
#line 88 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 88 "sample/undocked/map.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 88 "sample/undocked/map.c"
        return 0;
#line 88 "sample/undocked/map.c"
    }
label_18:
    // EBPF_OP_MOV64_IMM pc=226 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=227 dst=r10 src=r1 offset=-68 imm=0
#line 294 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-68)) = (uint8_t)r1;
    // EBPF_OP_MOV64_IMM pc=228 dst=r1 src=r0 offset=0 imm=1680154724
#line 294 "sample/undocked/map.c"
    r1 = IMMEDIATE(1680154724);
    // EBPF_OP_STXW pc=229 dst=r10 src=r1 offset=-72 imm=0
#line 294 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=230 dst=r1 src=r0 offset=0 imm=1952805408
#line 294 "sample/undocked/map.c"
    r1 = (uint64_t)7308905094058439200;
    // EBPF_OP_STXDW pc=232 dst=r10 src=r1 offset=-80 imm=0
#line 294 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=233 dst=r1 src=r0 offset=0 imm=1599426627
#line 294 "sample/undocked/map.c"
    r1 = (uint64_t)5211580972890673219;
    // EBPF_OP_STXDW pc=235 dst=r10 src=r1 offset=-88 imm=0
#line 294 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=236 dst=r1 src=r0 offset=0 imm=1885433120
#line 294 "sample/undocked/map.c"
    r1 = (uint64_t)5928232584757734688;
    // EBPF_OP_STXDW pc=238 dst=r10 src=r1 offset=-96 imm=0
#line 294 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=239 dst=r1 src=r0 offset=0 imm=1279349317
#line 294 "sample/undocked/map.c"
    r1 = (uint64_t)8245921731643003461;
    // EBPF_OP_STXDW pc=241 dst=r10 src=r1 offset=-104 imm=0
#line 294 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=242 dst=r1 src=r0 offset=0 imm=1953719636
#line 294 "sample/undocked/map.c"
    r1 = (uint64_t)5639992313069659476;
label_19:
    // EBPF_OP_STXDW pc=244 dst=r10 src=r1 offset=-112 imm=0
#line 294 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=245 dst=r3 src=r6 offset=0 imm=0
#line 294 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=246 dst=r3 src=r0 offset=0 imm=32
#line 294 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=247 dst=r3 src=r0 offset=0 imm=32
#line 294 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=248 dst=r1 src=r10 offset=0 imm=0
#line 294 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=249 dst=r1 src=r0 offset=0 imm=-112
#line 294 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=250 dst=r2 src=r0 offset=0 imm=45
#line 294 "sample/undocked/map.c"
    r2 = IMMEDIATE(45);
    // EBPF_OP_JA pc=251 dst=r0 src=r0 offset=-151 imm=0
#line 294 "sample/undocked/map.c"
    goto label_8;
label_20:
    // EBPF_OP_MOV64_REG pc=252 dst=r2 src=r10 offset=0 imm=0
#line 294 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=253 dst=r2 src=r0 offset=0 imm=-4
#line 92 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=254 dst=r3 src=r10 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=255 dst=r3 src=r0 offset=0 imm=-8
#line 92 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=256 dst=r1 src=r1 offset=0 imm=2
#line 92 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_MOV64_IMM pc=258 dst=r4 src=r0 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=259 dst=r0 src=r0 offset=0 imm=2
#line 92 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 92 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 92 "sample/undocked/map.c"
        return 0;
#line 92 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=260 dst=r6 src=r0 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=261 dst=r3 src=r6 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=262 dst=r3 src=r0 offset=0 imm=32
#line 92 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=263 dst=r3 src=r0 offset=0 imm=32
#line 92 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=264 dst=r3 src=r0 offset=1 imm=-1
#line 93 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 93 "sample/undocked/map.c"
        goto label_21;
#line 93 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=265 dst=r0 src=r0 offset=-102 imm=0
#line 93 "sample/undocked/map.c"
    goto label_13;
label_21:
    // EBPF_OP_MOV64_REG pc=266 dst=r2 src=r10 offset=0 imm=0
#line 93 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=267 dst=r2 src=r0 offset=0 imm=-4
#line 103 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=268 dst=r1 src=r1 offset=0 imm=2
#line 103 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[1].address);
    // EBPF_OP_CALL pc=270 dst=r0 src=r0 offset=0 imm=4
#line 103 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[5].address(r1, r2, r3, r4, r5, context);
#line 103 "sample/undocked/map.c"
    if ((runtime_context->helper_data[5].tail_call) && (r0 == 0)) {
#line 103 "sample/undocked/map.c"
        return 0;
#line 103 "sample/undocked/map.c"
    }
    // EBPF_OP_JNE_IMM pc=271 dst=r0 src=r0 offset=23 imm=0
#line 104 "sample/undocked/map.c"
    if (r0 != IMMEDIATE(0)) {
#line 104 "sample/undocked/map.c"
        goto label_22;
#line 104 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_IMM pc=272 dst=r1 src=r0 offset=0 imm=0
#line 104 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=273 dst=r10 src=r1 offset=-68 imm=0
#line 105 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-68)) = (uint8_t)r1;
    // EBPF_OP_MOV64_IMM pc=274 dst=r1 src=r0 offset=0 imm=1280070990
#line 105 "sample/undocked/map.c"
    r1 = IMMEDIATE(1280070990);
    // EBPF_OP_STXW pc=275 dst=r10 src=r1 offset=-72 imm=0
#line 105 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=276 dst=r1 src=r0 offset=0 imm=1920300133
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)2334102031925867621;
    // EBPF_OP_STXDW pc=278 dst=r10 src=r1 offset=-80 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=279 dst=r1 src=r0 offset=0 imm=1818582885
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)8223693201956233061;
    // EBPF_OP_STXDW pc=281 dst=r10 src=r1 offset=-88 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=282 dst=r1 src=r0 offset=0 imm=1683973230
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)8387229063778886766;
    // EBPF_OP_STXDW pc=284 dst=r10 src=r1 offset=-96 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=285 dst=r1 src=r0 offset=0 imm=1802465132
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)7016450394082471788;
    // EBPF_OP_STXDW pc=287 dst=r10 src=r1 offset=-104 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=288 dst=r1 src=r0 offset=0 imm=1600548962
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=290 dst=r10 src=r1 offset=-112 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=291 dst=r1 src=r10 offset=0 imm=0
#line 105 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=292 dst=r1 src=r0 offset=0 imm=-112
#line 105 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=293 dst=r2 src=r0 offset=0 imm=45
#line 105 "sample/undocked/map.c"
    r2 = IMMEDIATE(45);
    // EBPF_OP_JA pc=294 dst=r0 src=r0 offset=-99 imm=0
#line 105 "sample/undocked/map.c"
    goto label_15;
label_22:
    // EBPF_OP_MOV64_IMM pc=295 dst=r1 src=r0 offset=0 imm=0
#line 105 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=296 dst=r10 src=r1 offset=-4 imm=0
#line 70 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_IMM pc=297 dst=r1 src=r0 offset=0 imm=1
#line 70 "sample/undocked/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=298 dst=r10 src=r1 offset=-8 imm=0
#line 71 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=299 dst=r2 src=r10 offset=0 imm=0
#line 71 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=300 dst=r2 src=r0 offset=0 imm=-4
#line 71 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=301 dst=r3 src=r10 offset=0 imm=0
#line 71 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=302 dst=r3 src=r0 offset=0 imm=-8
#line 71 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=303 dst=r1 src=r1 offset=0 imm=3
#line 74 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[2].address);
    // EBPF_OP_MOV64_IMM pc=305 dst=r4 src=r0 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=306 dst=r0 src=r0 offset=0 imm=2
#line 74 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 74 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 74 "sample/undocked/map.c"
        return 0;
#line 74 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=307 dst=r6 src=r0 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=308 dst=r3 src=r6 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=309 dst=r3 src=r0 offset=0 imm=32
#line 74 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=310 dst=r3 src=r0 offset=0 imm=32
#line 74 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=311 dst=r3 src=r0 offset=9 imm=-1
#line 75 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 75 "sample/undocked/map.c"
        goto label_24;
#line 75 "sample/undocked/map.c"
    }
label_23:
    // EBPF_OP_LDDW pc=312 dst=r1 src=r0 offset=0 imm=1684369010
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=314 dst=r10 src=r1 offset=-88 imm=0
#line 75 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=315 dst=r1 src=r0 offset=0 imm=544040300
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=317 dst=r10 src=r1 offset=-96 imm=0
#line 75 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=318 dst=r1 src=r0 offset=0 imm=1633972341
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671142817909;
    // EBPF_OP_JA pc=320 dst=r0 src=r0 offset=45 imm=0
#line 75 "sample/undocked/map.c"
    goto label_26;
label_24:
    // EBPF_OP_MOV64_REG pc=321 dst=r2 src=r10 offset=0 imm=0
#line 75 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=322 dst=r2 src=r0 offset=0 imm=-4
#line 80 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=323 dst=r1 src=r1 offset=0 imm=3
#line 80 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[2].address);
    // EBPF_OP_CALL pc=325 dst=r0 src=r0 offset=0 imm=1
#line 80 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 80 "sample/undocked/map.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 80 "sample/undocked/map.c"
        return 0;
#line 80 "sample/undocked/map.c"
    }
    // EBPF_OP_JNE_IMM pc=326 dst=r0 src=r0 offset=21 imm=0
#line 81 "sample/undocked/map.c"
    if (r0 != IMMEDIATE(0)) {
#line 81 "sample/undocked/map.c"
        goto label_25;
#line 81 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_IMM pc=327 dst=r1 src=r0 offset=0 imm=76
#line 81 "sample/undocked/map.c"
    r1 = IMMEDIATE(76);
    // EBPF_OP_STXH pc=328 dst=r10 src=r1 offset=-80 imm=0
#line 82 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=329 dst=r1 src=r0 offset=0 imm=1684369010
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)5500388420933217906;
    // EBPF_OP_STXDW pc=331 dst=r10 src=r1 offset=-88 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=332 dst=r1 src=r0 offset=0 imm=544040300
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=334 dst=r10 src=r1 offset=-96 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=335 dst=r1 src=r0 offset=0 imm=1802465132
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)7304680770234183532;
    // EBPF_OP_STXDW pc=337 dst=r10 src=r1 offset=-104 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=338 dst=r1 src=r0 offset=0 imm=1600548962
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=340 dst=r10 src=r1 offset=-112 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=341 dst=r1 src=r10 offset=0 imm=0
#line 82 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=342 dst=r1 src=r0 offset=0 imm=-112
#line 82 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=343 dst=r2 src=r0 offset=0 imm=34
#line 82 "sample/undocked/map.c"
    r2 = IMMEDIATE(34);
    // EBPF_OP_CALL pc=344 dst=r0 src=r0 offset=0 imm=12
#line 82 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 82 "sample/undocked/map.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 82 "sample/undocked/map.c"
        return 0;
#line 82 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=345 dst=r6 src=r0 offset=0 imm=-1
#line 82 "sample/undocked/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JA pc=347 dst=r0 src=r0 offset=26 imm=0
#line 82 "sample/undocked/map.c"
    goto label_27;
label_25:
    // EBPF_OP_MOV64_REG pc=348 dst=r2 src=r10 offset=0 imm=0
#line 82 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=349 dst=r2 src=r0 offset=0 imm=-4
#line 86 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=350 dst=r1 src=r1 offset=0 imm=3
#line 86 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[2].address);
    // EBPF_OP_CALL pc=352 dst=r0 src=r0 offset=0 imm=3
#line 86 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
#line 86 "sample/undocked/map.c"
    if ((runtime_context->helper_data[3].tail_call) && (r0 == 0)) {
#line 86 "sample/undocked/map.c"
        return 0;
#line 86 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=353 dst=r6 src=r0 offset=0 imm=0
#line 86 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=354 dst=r3 src=r6 offset=0 imm=0
#line 86 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=355 dst=r3 src=r0 offset=0 imm=32
#line 86 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=356 dst=r3 src=r0 offset=0 imm=32
#line 86 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=357 dst=r3 src=r0 offset=41 imm=-1
#line 87 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 87 "sample/undocked/map.c"
        goto label_28;
#line 87 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=358 dst=r1 src=r0 offset=0 imm=1684369010
#line 87 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=360 dst=r10 src=r1 offset=-88 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=361 dst=r1 src=r0 offset=0 imm=544040300
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=363 dst=r10 src=r1 offset=-96 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=364 dst=r1 src=r0 offset=0 imm=1701602660
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671210448228;
label_26:
    // EBPF_OP_STXDW pc=366 dst=r10 src=r1 offset=-104 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=367 dst=r1 src=r0 offset=0 imm=1600548962
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=369 dst=r10 src=r1 offset=-112 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=370 dst=r1 src=r10 offset=0 imm=0
#line 88 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=371 dst=r1 src=r0 offset=0 imm=-112
#line 88 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=372 dst=r2 src=r0 offset=0 imm=32
#line 88 "sample/undocked/map.c"
    r2 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=373 dst=r0 src=r0 offset=0 imm=13
#line 88 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 88 "sample/undocked/map.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 88 "sample/undocked/map.c"
        return 0;
#line 88 "sample/undocked/map.c"
    }
label_27:
    // EBPF_OP_MOV64_IMM pc=374 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=375 dst=r10 src=r1 offset=-74 imm=0
#line 295 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-74)) = (uint8_t)r1;
    // EBPF_OP_MOV64_IMM pc=376 dst=r1 src=r0 offset=0 imm=25637
#line 295 "sample/undocked/map.c"
    r1 = IMMEDIATE(25637);
    // EBPF_OP_STXH pc=377 dst=r10 src=r1 offset=-76 imm=0
#line 295 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-76)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=378 dst=r1 src=r0 offset=0 imm=543450478
#line 295 "sample/undocked/map.c"
    r1 = IMMEDIATE(543450478);
    // EBPF_OP_STXW pc=379 dst=r10 src=r1 offset=-80 imm=0
#line 295 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=380 dst=r1 src=r0 offset=0 imm=1914722625
#line 295 "sample/undocked/map.c"
    r1 = (uint64_t)8247626271654172993;
    // EBPF_OP_STXDW pc=382 dst=r10 src=r1 offset=-88 imm=0
#line 295 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=383 dst=r1 src=r0 offset=0 imm=1885433120
#line 295 "sample/undocked/map.c"
    r1 = (uint64_t)5931875266780556576;
    // EBPF_OP_STXDW pc=385 dst=r10 src=r1 offset=-96 imm=0
#line 295 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=386 dst=r1 src=r0 offset=0 imm=1279349317
#line 295 "sample/undocked/map.c"
    r1 = (uint64_t)8245921731643003461;
    // EBPF_OP_STXDW pc=388 dst=r10 src=r1 offset=-104 imm=0
#line 295 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=389 dst=r1 src=r0 offset=0 imm=1953719636
#line 295 "sample/undocked/map.c"
    r1 = (uint64_t)5639992313069659476;
    // EBPF_OP_STXDW pc=391 dst=r10 src=r1 offset=-112 imm=0
#line 295 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=392 dst=r3 src=r6 offset=0 imm=0
#line 295 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=393 dst=r3 src=r0 offset=0 imm=32
#line 295 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=394 dst=r3 src=r0 offset=0 imm=32
#line 295 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=395 dst=r1 src=r10 offset=0 imm=0
#line 295 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=396 dst=r1 src=r0 offset=0 imm=-112
#line 295 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=397 dst=r2 src=r0 offset=0 imm=39
#line 295 "sample/undocked/map.c"
    r2 = IMMEDIATE(39);
    // EBPF_OP_JA pc=398 dst=r0 src=r0 offset=-298 imm=0
#line 295 "sample/undocked/map.c"
    goto label_8;
label_28:
    // EBPF_OP_MOV64_REG pc=399 dst=r2 src=r10 offset=0 imm=0
#line 295 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=400 dst=r2 src=r0 offset=0 imm=-4
#line 92 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=401 dst=r3 src=r10 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=402 dst=r3 src=r0 offset=0 imm=-8
#line 92 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_IMM pc=403 dst=r7 src=r0 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=404 dst=r1 src=r1 offset=0 imm=3
#line 92 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[2].address);
    // EBPF_OP_MOV64_IMM pc=406 dst=r4 src=r0 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=407 dst=r0 src=r0 offset=0 imm=2
#line 92 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 92 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 92 "sample/undocked/map.c"
        return 0;
#line 92 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=408 dst=r6 src=r0 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=409 dst=r3 src=r6 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=410 dst=r3 src=r0 offset=0 imm=32
#line 92 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=411 dst=r3 src=r0 offset=0 imm=32
#line 92 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=412 dst=r3 src=r0 offset=1 imm=-1
#line 93 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 93 "sample/undocked/map.c"
        goto label_29;
#line 93 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=413 dst=r0 src=r0 offset=-102 imm=0
#line 93 "sample/undocked/map.c"
    goto label_23;
label_29:
    // EBPF_OP_STXW pc=414 dst=r10 src=r7 offset=-4 imm=0
#line 70 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_IMM pc=415 dst=r1 src=r0 offset=0 imm=1
#line 70 "sample/undocked/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=416 dst=r10 src=r1 offset=-8 imm=0
#line 71 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=417 dst=r2 src=r10 offset=0 imm=0
#line 71 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=418 dst=r2 src=r0 offset=0 imm=-4
#line 71 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=419 dst=r3 src=r10 offset=0 imm=0
#line 71 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=420 dst=r3 src=r0 offset=0 imm=-8
#line 71 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=421 dst=r1 src=r1 offset=0 imm=4
#line 74 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[3].address);
    // EBPF_OP_MOV64_IMM pc=423 dst=r4 src=r0 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=424 dst=r0 src=r0 offset=0 imm=2
#line 74 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 74 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 74 "sample/undocked/map.c"
        return 0;
#line 74 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=425 dst=r6 src=r0 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=426 dst=r3 src=r6 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=427 dst=r3 src=r0 offset=0 imm=32
#line 74 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=428 dst=r3 src=r0 offset=0 imm=32
#line 74 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_REG pc=429 dst=r7 src=r3 offset=59 imm=0
#line 75 "sample/undocked/map.c"
    if ((int64_t)r7 > (int64_t)r3) {
#line 75 "sample/undocked/map.c"
        goto label_32;
#line 75 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=430 dst=r2 src=r10 offset=0 imm=0
#line 75 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=431 dst=r2 src=r0 offset=0 imm=-4
#line 80 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=432 dst=r1 src=r1 offset=0 imm=4
#line 80 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[3].address);
    // EBPF_OP_CALL pc=434 dst=r0 src=r0 offset=0 imm=1
#line 80 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 80 "sample/undocked/map.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 80 "sample/undocked/map.c"
        return 0;
#line 80 "sample/undocked/map.c"
    }
    // EBPF_OP_JNE_IMM pc=435 dst=r0 src=r0 offset=21 imm=0
#line 81 "sample/undocked/map.c"
    if (r0 != IMMEDIATE(0)) {
#line 81 "sample/undocked/map.c"
        goto label_30;
#line 81 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_IMM pc=436 dst=r1 src=r0 offset=0 imm=76
#line 81 "sample/undocked/map.c"
    r1 = IMMEDIATE(76);
    // EBPF_OP_STXH pc=437 dst=r10 src=r1 offset=-80 imm=0
#line 82 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=438 dst=r1 src=r0 offset=0 imm=1684369010
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)5500388420933217906;
    // EBPF_OP_STXDW pc=440 dst=r10 src=r1 offset=-88 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=441 dst=r1 src=r0 offset=0 imm=544040300
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=443 dst=r10 src=r1 offset=-96 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=444 dst=r1 src=r0 offset=0 imm=1802465132
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)7304680770234183532;
    // EBPF_OP_STXDW pc=446 dst=r10 src=r1 offset=-104 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=447 dst=r1 src=r0 offset=0 imm=1600548962
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=449 dst=r10 src=r1 offset=-112 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=450 dst=r1 src=r10 offset=0 imm=0
#line 82 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=451 dst=r1 src=r0 offset=0 imm=-112
#line 82 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=452 dst=r2 src=r0 offset=0 imm=34
#line 82 "sample/undocked/map.c"
    r2 = IMMEDIATE(34);
    // EBPF_OP_CALL pc=453 dst=r0 src=r0 offset=0 imm=12
#line 82 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 82 "sample/undocked/map.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 82 "sample/undocked/map.c"
        return 0;
#line 82 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=454 dst=r6 src=r0 offset=0 imm=-1
#line 82 "sample/undocked/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JA pc=456 dst=r0 src=r0 offset=48 imm=0
#line 82 "sample/undocked/map.c"
    goto label_34;
label_30:
    // EBPF_OP_MOV64_REG pc=457 dst=r2 src=r10 offset=0 imm=0
#line 82 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=458 dst=r2 src=r0 offset=0 imm=-4
#line 86 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=459 dst=r1 src=r1 offset=0 imm=4
#line 86 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[3].address);
    // EBPF_OP_CALL pc=461 dst=r0 src=r0 offset=0 imm=3
#line 86 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
#line 86 "sample/undocked/map.c"
    if ((runtime_context->helper_data[3].tail_call) && (r0 == 0)) {
#line 86 "sample/undocked/map.c"
        return 0;
#line 86 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=462 dst=r6 src=r0 offset=0 imm=0
#line 86 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=463 dst=r3 src=r6 offset=0 imm=0
#line 86 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=464 dst=r3 src=r0 offset=0 imm=32
#line 86 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=465 dst=r3 src=r0 offset=0 imm=32
#line 86 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=466 dst=r3 src=r0 offset=9 imm=-1
#line 87 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 87 "sample/undocked/map.c"
        goto label_31;
#line 87 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=467 dst=r1 src=r0 offset=0 imm=1684369010
#line 87 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=469 dst=r10 src=r1 offset=-88 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=470 dst=r1 src=r0 offset=0 imm=544040300
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=472 dst=r10 src=r1 offset=-96 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=473 dst=r1 src=r0 offset=0 imm=1701602660
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671210448228;
    // EBPF_OP_JA pc=475 dst=r0 src=r0 offset=21 imm=0
#line 88 "sample/undocked/map.c"
    goto label_33;
label_31:
    // EBPF_OP_MOV64_REG pc=476 dst=r2 src=r10 offset=0 imm=0
#line 88 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=477 dst=r2 src=r0 offset=0 imm=-4
#line 92 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=478 dst=r3 src=r10 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=479 dst=r3 src=r0 offset=0 imm=-8
#line 92 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=480 dst=r1 src=r1 offset=0 imm=4
#line 92 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[3].address);
    // EBPF_OP_MOV64_IMM pc=482 dst=r4 src=r0 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=483 dst=r0 src=r0 offset=0 imm=2
#line 92 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 92 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 92 "sample/undocked/map.c"
        return 0;
#line 92 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=484 dst=r6 src=r0 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=485 dst=r3 src=r6 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=486 dst=r3 src=r0 offset=0 imm=32
#line 92 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=487 dst=r3 src=r0 offset=0 imm=32
#line 92 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=488 dst=r3 src=r0 offset=42 imm=-1
#line 93 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 93 "sample/undocked/map.c"
        goto label_35;
#line 93 "sample/undocked/map.c"
    }
label_32:
    // EBPF_OP_LDDW pc=489 dst=r1 src=r0 offset=0 imm=1684369010
#line 93 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=491 dst=r10 src=r1 offset=-88 imm=0
#line 93 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=492 dst=r1 src=r0 offset=0 imm=544040300
#line 93 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=494 dst=r10 src=r1 offset=-96 imm=0
#line 93 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=495 dst=r1 src=r0 offset=0 imm=1633972341
#line 93 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671142817909;
label_33:
    // EBPF_OP_STXDW pc=497 dst=r10 src=r1 offset=-104 imm=0
#line 93 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=498 dst=r1 src=r0 offset=0 imm=1600548962
#line 93 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=500 dst=r10 src=r1 offset=-112 imm=0
#line 93 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=501 dst=r1 src=r10 offset=0 imm=0
#line 93 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=502 dst=r1 src=r0 offset=0 imm=-112
#line 93 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=503 dst=r2 src=r0 offset=0 imm=32
#line 93 "sample/undocked/map.c"
    r2 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=504 dst=r0 src=r0 offset=0 imm=13
#line 93 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 93 "sample/undocked/map.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 93 "sample/undocked/map.c"
        return 0;
#line 93 "sample/undocked/map.c"
    }
label_34:
    // EBPF_OP_MOV64_IMM pc=505 dst=r1 src=r0 offset=0 imm=100
#line 93 "sample/undocked/map.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXH pc=506 dst=r10 src=r1 offset=-68 imm=0
#line 296 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-68)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=507 dst=r1 src=r0 offset=0 imm=622879845
#line 296 "sample/undocked/map.c"
    r1 = IMMEDIATE(622879845);
    // EBPF_OP_STXW pc=508 dst=r10 src=r1 offset=-72 imm=0
#line 296 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=509 dst=r1 src=r0 offset=0 imm=1701978201
#line 296 "sample/undocked/map.c"
    r1 = (uint64_t)7958552634295722073;
    // EBPF_OP_STXDW pc=511 dst=r10 src=r1 offset=-80 imm=0
#line 296 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=512 dst=r1 src=r0 offset=0 imm=1599426627
#line 296 "sample/undocked/map.c"
    r1 = (uint64_t)4706915001281368131;
    // EBPF_OP_STXDW pc=514 dst=r10 src=r1 offset=-88 imm=0
#line 296 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=515 dst=r1 src=r0 offset=0 imm=1885433120
#line 296 "sample/undocked/map.c"
    r1 = (uint64_t)5928232584757734688;
    // EBPF_OP_STXDW pc=517 dst=r10 src=r1 offset=-96 imm=0
#line 296 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=518 dst=r1 src=r0 offset=0 imm=1279349317
#line 296 "sample/undocked/map.c"
    r1 = (uint64_t)8245921731643003461;
    // EBPF_OP_STXDW pc=520 dst=r10 src=r1 offset=-104 imm=0
#line 296 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=521 dst=r1 src=r0 offset=0 imm=1953719636
#line 296 "sample/undocked/map.c"
    r1 = (uint64_t)5639992313069659476;
    // EBPF_OP_STXDW pc=523 dst=r10 src=r1 offset=-112 imm=0
#line 296 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=524 dst=r3 src=r6 offset=0 imm=0
#line 296 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=525 dst=r3 src=r0 offset=0 imm=32
#line 296 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=526 dst=r3 src=r0 offset=0 imm=32
#line 296 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=527 dst=r1 src=r10 offset=0 imm=0
#line 296 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=528 dst=r1 src=r0 offset=0 imm=-112
#line 296 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=529 dst=r2 src=r0 offset=0 imm=46
#line 296 "sample/undocked/map.c"
    r2 = IMMEDIATE(46);
    // EBPF_OP_JA pc=530 dst=r0 src=r0 offset=-430 imm=0
#line 296 "sample/undocked/map.c"
    goto label_8;
label_35:
    // EBPF_OP_STXW pc=531 dst=r10 src=r7 offset=-4 imm=0
#line 70 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_IMM pc=532 dst=r1 src=r0 offset=0 imm=1
#line 70 "sample/undocked/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=533 dst=r10 src=r1 offset=-8 imm=0
#line 71 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=534 dst=r2 src=r10 offset=0 imm=0
#line 71 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=535 dst=r2 src=r0 offset=0 imm=-4
#line 71 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=536 dst=r3 src=r10 offset=0 imm=0
#line 71 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=537 dst=r3 src=r0 offset=0 imm=-8
#line 71 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=538 dst=r1 src=r1 offset=0 imm=5
#line 74 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[4].address);
    // EBPF_OP_MOV64_IMM pc=540 dst=r4 src=r0 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=541 dst=r0 src=r0 offset=0 imm=2
#line 74 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 74 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 74 "sample/undocked/map.c"
        return 0;
#line 74 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=542 dst=r6 src=r0 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=543 dst=r3 src=r6 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=544 dst=r3 src=r0 offset=0 imm=32
#line 74 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=545 dst=r3 src=r0 offset=0 imm=32
#line 74 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=546 dst=r3 src=r0 offset=9 imm=-1
#line 75 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 75 "sample/undocked/map.c"
        goto label_37;
#line 75 "sample/undocked/map.c"
    }
label_36:
    // EBPF_OP_LDDW pc=547 dst=r1 src=r0 offset=0 imm=1684369010
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=549 dst=r10 src=r1 offset=-88 imm=0
#line 75 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=550 dst=r1 src=r0 offset=0 imm=544040300
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=552 dst=r10 src=r1 offset=-96 imm=0
#line 75 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=553 dst=r1 src=r0 offset=0 imm=1633972341
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671142817909;
    // EBPF_OP_JA pc=555 dst=r0 src=r0 offset=45 imm=0
#line 75 "sample/undocked/map.c"
    goto label_40;
label_37:
    // EBPF_OP_MOV64_REG pc=556 dst=r2 src=r10 offset=0 imm=0
#line 75 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=557 dst=r2 src=r0 offset=0 imm=-4
#line 80 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=558 dst=r1 src=r1 offset=0 imm=5
#line 80 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[4].address);
    // EBPF_OP_CALL pc=560 dst=r0 src=r0 offset=0 imm=1
#line 80 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 80 "sample/undocked/map.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 80 "sample/undocked/map.c"
        return 0;
#line 80 "sample/undocked/map.c"
    }
    // EBPF_OP_JNE_IMM pc=561 dst=r0 src=r0 offset=21 imm=0
#line 81 "sample/undocked/map.c"
    if (r0 != IMMEDIATE(0)) {
#line 81 "sample/undocked/map.c"
        goto label_39;
#line 81 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_IMM pc=562 dst=r1 src=r0 offset=0 imm=76
#line 81 "sample/undocked/map.c"
    r1 = IMMEDIATE(76);
    // EBPF_OP_STXH pc=563 dst=r10 src=r1 offset=-80 imm=0
#line 82 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=564 dst=r1 src=r0 offset=0 imm=1684369010
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)5500388420933217906;
    // EBPF_OP_STXDW pc=566 dst=r10 src=r1 offset=-88 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=567 dst=r1 src=r0 offset=0 imm=544040300
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=569 dst=r10 src=r1 offset=-96 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=570 dst=r1 src=r0 offset=0 imm=1802465132
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)7304680770234183532;
    // EBPF_OP_STXDW pc=572 dst=r10 src=r1 offset=-104 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=573 dst=r1 src=r0 offset=0 imm=1600548962
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=575 dst=r10 src=r1 offset=-112 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=576 dst=r1 src=r10 offset=0 imm=0
#line 82 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=577 dst=r1 src=r0 offset=0 imm=-112
#line 82 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=578 dst=r2 src=r0 offset=0 imm=34
#line 82 "sample/undocked/map.c"
    r2 = IMMEDIATE(34);
label_38:
    // EBPF_OP_CALL pc=579 dst=r0 src=r0 offset=0 imm=12
#line 82 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 82 "sample/undocked/map.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 82 "sample/undocked/map.c"
        return 0;
#line 82 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=580 dst=r6 src=r0 offset=0 imm=-1
#line 82 "sample/undocked/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JA pc=582 dst=r0 src=r0 offset=26 imm=0
#line 82 "sample/undocked/map.c"
    goto label_41;
label_39:
    // EBPF_OP_MOV64_REG pc=583 dst=r2 src=r10 offset=0 imm=0
#line 82 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=584 dst=r2 src=r0 offset=0 imm=-4
#line 86 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=585 dst=r1 src=r1 offset=0 imm=5
#line 86 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[4].address);
    // EBPF_OP_CALL pc=587 dst=r0 src=r0 offset=0 imm=3
#line 86 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
#line 86 "sample/undocked/map.c"
    if ((runtime_context->helper_data[3].tail_call) && (r0 == 0)) {
#line 86 "sample/undocked/map.c"
        return 0;
#line 86 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=588 dst=r6 src=r0 offset=0 imm=0
#line 86 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=589 dst=r3 src=r6 offset=0 imm=0
#line 86 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=590 dst=r3 src=r0 offset=0 imm=32
#line 86 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=591 dst=r3 src=r0 offset=0 imm=32
#line 86 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=592 dst=r3 src=r0 offset=40 imm=-1
#line 87 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 87 "sample/undocked/map.c"
        goto label_42;
#line 87 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=593 dst=r1 src=r0 offset=0 imm=1684369010
#line 87 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=595 dst=r10 src=r1 offset=-88 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=596 dst=r1 src=r0 offset=0 imm=544040300
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=598 dst=r10 src=r1 offset=-96 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=599 dst=r1 src=r0 offset=0 imm=1701602660
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671210448228;
label_40:
    // EBPF_OP_STXDW pc=601 dst=r10 src=r1 offset=-104 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=602 dst=r1 src=r0 offset=0 imm=1600548962
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=604 dst=r10 src=r1 offset=-112 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=605 dst=r1 src=r10 offset=0 imm=0
#line 88 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=606 dst=r1 src=r0 offset=0 imm=-112
#line 88 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=607 dst=r2 src=r0 offset=0 imm=32
#line 88 "sample/undocked/map.c"
    r2 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=608 dst=r0 src=r0 offset=0 imm=13
#line 88 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 88 "sample/undocked/map.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 88 "sample/undocked/map.c"
        return 0;
#line 88 "sample/undocked/map.c"
    }
label_41:
    // EBPF_OP_MOV64_IMM pc=609 dst=r1 src=r0 offset=0 imm=100
#line 88 "sample/undocked/map.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXH pc=610 dst=r10 src=r1 offset=-72 imm=0
#line 297 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=611 dst=r1 src=r0 offset=0 imm=1852994932
#line 297 "sample/undocked/map.c"
    r1 = (uint64_t)2675248565465544052;
    // EBPF_OP_STXDW pc=613 dst=r10 src=r1 offset=-80 imm=0
#line 297 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=614 dst=r1 src=r0 offset=0 imm=1396787295
#line 297 "sample/undocked/map.c"
    r1 = (uint64_t)7309940640182257759;
    // EBPF_OP_STXDW pc=616 dst=r10 src=r1 offset=-88 imm=0
#line 297 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=617 dst=r1 src=r0 offset=0 imm=1885433120
#line 297 "sample/undocked/map.c"
    r1 = (uint64_t)6148060143522245920;
    // EBPF_OP_STXDW pc=619 dst=r10 src=r1 offset=-96 imm=0
#line 297 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=620 dst=r1 src=r0 offset=0 imm=1279349317
#line 297 "sample/undocked/map.c"
    r1 = (uint64_t)8245921731643003461;
    // EBPF_OP_STXDW pc=622 dst=r10 src=r1 offset=-104 imm=0
#line 297 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=623 dst=r1 src=r0 offset=0 imm=1953719636
#line 297 "sample/undocked/map.c"
    r1 = (uint64_t)5639992313069659476;
    // EBPF_OP_STXDW pc=625 dst=r10 src=r1 offset=-112 imm=0
#line 297 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=626 dst=r3 src=r6 offset=0 imm=0
#line 297 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=627 dst=r3 src=r0 offset=0 imm=32
#line 297 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=628 dst=r3 src=r0 offset=0 imm=32
#line 297 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=629 dst=r1 src=r10 offset=0 imm=0
#line 297 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=630 dst=r1 src=r0 offset=0 imm=-112
#line 297 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=631 dst=r2 src=r0 offset=0 imm=42
#line 297 "sample/undocked/map.c"
    r2 = IMMEDIATE(42);
    // EBPF_OP_JA pc=632 dst=r0 src=r0 offset=-532 imm=0
#line 297 "sample/undocked/map.c"
    goto label_8;
label_42:
    // EBPF_OP_MOV64_REG pc=633 dst=r2 src=r10 offset=0 imm=0
#line 297 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=634 dst=r2 src=r0 offset=0 imm=-4
#line 92 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=635 dst=r3 src=r10 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=636 dst=r3 src=r0 offset=0 imm=-8
#line 92 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=637 dst=r1 src=r1 offset=0 imm=5
#line 92 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[4].address);
    // EBPF_OP_MOV64_IMM pc=639 dst=r4 src=r0 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=640 dst=r0 src=r0 offset=0 imm=2
#line 92 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 92 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 92 "sample/undocked/map.c"
        return 0;
#line 92 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=641 dst=r6 src=r0 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=642 dst=r3 src=r6 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=643 dst=r3 src=r0 offset=0 imm=32
#line 92 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=644 dst=r3 src=r0 offset=0 imm=32
#line 92 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=645 dst=r3 src=r0 offset=1 imm=-1
#line 93 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 93 "sample/undocked/map.c"
        goto label_43;
#line 93 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=646 dst=r0 src=r0 offset=-100 imm=0
#line 93 "sample/undocked/map.c"
    goto label_36;
label_43:
    // EBPF_OP_MOV64_REG pc=647 dst=r2 src=r10 offset=0 imm=0
#line 93 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=648 dst=r2 src=r0 offset=0 imm=-4
#line 103 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=649 dst=r1 src=r1 offset=0 imm=5
#line 103 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[4].address);
    // EBPF_OP_CALL pc=651 dst=r0 src=r0 offset=0 imm=4
#line 103 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[5].address(r1, r2, r3, r4, r5, context);
#line 103 "sample/undocked/map.c"
    if ((runtime_context->helper_data[5].tail_call) && (r0 == 0)) {
#line 103 "sample/undocked/map.c"
        return 0;
#line 103 "sample/undocked/map.c"
    }
    // EBPF_OP_JNE_IMM pc=652 dst=r0 src=r0 offset=23 imm=0
#line 104 "sample/undocked/map.c"
    if (r0 != IMMEDIATE(0)) {
#line 104 "sample/undocked/map.c"
        goto label_44;
#line 104 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_IMM pc=653 dst=r1 src=r0 offset=0 imm=0
#line 104 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=654 dst=r10 src=r1 offset=-68 imm=0
#line 105 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-68)) = (uint8_t)r1;
    // EBPF_OP_MOV64_IMM pc=655 dst=r1 src=r0 offset=0 imm=1280070990
#line 105 "sample/undocked/map.c"
    r1 = IMMEDIATE(1280070990);
    // EBPF_OP_STXW pc=656 dst=r10 src=r1 offset=-72 imm=0
#line 105 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=657 dst=r1 src=r0 offset=0 imm=1920300133
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)2334102031925867621;
    // EBPF_OP_STXDW pc=659 dst=r10 src=r1 offset=-80 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=660 dst=r1 src=r0 offset=0 imm=1818582885
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)8223693201956233061;
    // EBPF_OP_STXDW pc=662 dst=r10 src=r1 offset=-88 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=663 dst=r1 src=r0 offset=0 imm=1683973230
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)8387229063778886766;
    // EBPF_OP_STXDW pc=665 dst=r10 src=r1 offset=-96 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=666 dst=r1 src=r0 offset=0 imm=1802465132
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)7016450394082471788;
    // EBPF_OP_STXDW pc=668 dst=r10 src=r1 offset=-104 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=669 dst=r1 src=r0 offset=0 imm=1600548962
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=671 dst=r10 src=r1 offset=-112 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=672 dst=r1 src=r10 offset=0 imm=0
#line 105 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=673 dst=r1 src=r0 offset=0 imm=-112
#line 105 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=674 dst=r2 src=r0 offset=0 imm=45
#line 105 "sample/undocked/map.c"
    r2 = IMMEDIATE(45);
    // EBPF_OP_JA pc=675 dst=r0 src=r0 offset=-97 imm=0
#line 105 "sample/undocked/map.c"
    goto label_38;
label_44:
    // EBPF_OP_MOV64_IMM pc=676 dst=r1 src=r0 offset=0 imm=0
#line 105 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=677 dst=r10 src=r1 offset=-4 imm=0
#line 70 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_IMM pc=678 dst=r1 src=r0 offset=0 imm=1
#line 70 "sample/undocked/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=679 dst=r10 src=r1 offset=-8 imm=0
#line 71 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=680 dst=r2 src=r10 offset=0 imm=0
#line 71 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=681 dst=r2 src=r0 offset=0 imm=-4
#line 71 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=682 dst=r3 src=r10 offset=0 imm=0
#line 71 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=683 dst=r3 src=r0 offset=0 imm=-8
#line 71 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=684 dst=r1 src=r1 offset=0 imm=6
#line 74 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[5].address);
    // EBPF_OP_MOV64_IMM pc=686 dst=r4 src=r0 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=687 dst=r0 src=r0 offset=0 imm=2
#line 74 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 74 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 74 "sample/undocked/map.c"
        return 0;
#line 74 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=688 dst=r6 src=r0 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=689 dst=r3 src=r6 offset=0 imm=0
#line 74 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=690 dst=r3 src=r0 offset=0 imm=32
#line 74 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=691 dst=r3 src=r0 offset=0 imm=32
#line 74 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=692 dst=r3 src=r0 offset=9 imm=-1
#line 75 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 75 "sample/undocked/map.c"
        goto label_46;
#line 75 "sample/undocked/map.c"
    }
label_45:
    // EBPF_OP_LDDW pc=693 dst=r1 src=r0 offset=0 imm=1684369010
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=695 dst=r10 src=r1 offset=-88 imm=0
#line 75 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=696 dst=r1 src=r0 offset=0 imm=544040300
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=698 dst=r10 src=r1 offset=-96 imm=0
#line 75 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=699 dst=r1 src=r0 offset=0 imm=1633972341
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671142817909;
    // EBPF_OP_JA pc=701 dst=r0 src=r0 offset=45 imm=0
#line 75 "sample/undocked/map.c"
    goto label_49;
label_46:
    // EBPF_OP_MOV64_REG pc=702 dst=r2 src=r10 offset=0 imm=0
#line 75 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=703 dst=r2 src=r0 offset=0 imm=-4
#line 80 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=704 dst=r1 src=r1 offset=0 imm=6
#line 80 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[5].address);
    // EBPF_OP_CALL pc=706 dst=r0 src=r0 offset=0 imm=1
#line 80 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 80 "sample/undocked/map.c"
    if ((runtime_context->helper_data[1].tail_call) && (r0 == 0)) {
#line 80 "sample/undocked/map.c"
        return 0;
#line 80 "sample/undocked/map.c"
    }
    // EBPF_OP_JNE_IMM pc=707 dst=r0 src=r0 offset=21 imm=0
#line 81 "sample/undocked/map.c"
    if (r0 != IMMEDIATE(0)) {
#line 81 "sample/undocked/map.c"
        goto label_48;
#line 81 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_IMM pc=708 dst=r1 src=r0 offset=0 imm=76
#line 81 "sample/undocked/map.c"
    r1 = IMMEDIATE(76);
    // EBPF_OP_STXH pc=709 dst=r10 src=r1 offset=-80 imm=0
#line 82 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=710 dst=r1 src=r0 offset=0 imm=1684369010
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)5500388420933217906;
    // EBPF_OP_STXDW pc=712 dst=r10 src=r1 offset=-88 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=713 dst=r1 src=r0 offset=0 imm=544040300
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=715 dst=r10 src=r1 offset=-96 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=716 dst=r1 src=r0 offset=0 imm=1802465132
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)7304680770234183532;
    // EBPF_OP_STXDW pc=718 dst=r10 src=r1 offset=-104 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=719 dst=r1 src=r0 offset=0 imm=1600548962
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=721 dst=r10 src=r1 offset=-112 imm=0
#line 82 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=722 dst=r1 src=r10 offset=0 imm=0
#line 82 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=723 dst=r1 src=r0 offset=0 imm=-112
#line 82 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=724 dst=r2 src=r0 offset=0 imm=34
#line 82 "sample/undocked/map.c"
    r2 = IMMEDIATE(34);
label_47:
    // EBPF_OP_CALL pc=725 dst=r0 src=r0 offset=0 imm=12
#line 82 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 82 "sample/undocked/map.c"
    if ((runtime_context->helper_data[2].tail_call) && (r0 == 0)) {
#line 82 "sample/undocked/map.c"
        return 0;
#line 82 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=726 dst=r6 src=r0 offset=0 imm=-1
#line 82 "sample/undocked/map.c"
    r6 = (uint64_t)4294967295;
    // EBPF_OP_JA pc=728 dst=r0 src=r0 offset=26 imm=0
#line 82 "sample/undocked/map.c"
    goto label_50;
label_48:
    // EBPF_OP_MOV64_REG pc=729 dst=r2 src=r10 offset=0 imm=0
#line 82 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=730 dst=r2 src=r0 offset=0 imm=-4
#line 86 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=731 dst=r1 src=r1 offset=0 imm=6
#line 86 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[5].address);
    // EBPF_OP_CALL pc=733 dst=r0 src=r0 offset=0 imm=3
#line 86 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
#line 86 "sample/undocked/map.c"
    if ((runtime_context->helper_data[3].tail_call) && (r0 == 0)) {
#line 86 "sample/undocked/map.c"
        return 0;
#line 86 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=734 dst=r6 src=r0 offset=0 imm=0
#line 86 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=735 dst=r3 src=r6 offset=0 imm=0
#line 86 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=736 dst=r3 src=r0 offset=0 imm=32
#line 86 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=737 dst=r3 src=r0 offset=0 imm=32
#line 86 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=738 dst=r3 src=r0 offset=43 imm=-1
#line 87 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 87 "sample/undocked/map.c"
        goto label_51;
#line 87 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=739 dst=r1 src=r0 offset=0 imm=1684369010
#line 87 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=741 dst=r10 src=r1 offset=-88 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=742 dst=r1 src=r0 offset=0 imm=544040300
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=744 dst=r10 src=r1 offset=-96 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=745 dst=r1 src=r0 offset=0 imm=1701602660
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671210448228;
label_49:
    // EBPF_OP_STXDW pc=747 dst=r10 src=r1 offset=-104 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=748 dst=r1 src=r0 offset=0 imm=1600548962
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=750 dst=r10 src=r1 offset=-112 imm=0
#line 88 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=751 dst=r1 src=r10 offset=0 imm=0
#line 88 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=752 dst=r1 src=r0 offset=0 imm=-112
#line 88 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=753 dst=r2 src=r0 offset=0 imm=32
#line 88 "sample/undocked/map.c"
    r2 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=754 dst=r0 src=r0 offset=0 imm=13
#line 88 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 88 "sample/undocked/map.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 88 "sample/undocked/map.c"
        return 0;
#line 88 "sample/undocked/map.c"
    }
label_50:
    // EBPF_OP_MOV64_IMM pc=755 dst=r1 src=r0 offset=0 imm=0
#line 88 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=756 dst=r10 src=r1 offset=-64 imm=0
#line 298 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint8_t)r1;
    // EBPF_OP_LDDW pc=757 dst=r1 src=r0 offset=0 imm=1701737077
#line 298 "sample/undocked/map.c"
    r1 = (uint64_t)7216209593501643381;
    // EBPF_OP_STXDW pc=759 dst=r10 src=r1 offset=-72 imm=0
#line 298 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=760 dst=r1 src=r0 offset=0 imm=1213415752
#line 298 "sample/undocked/map.c"
    r1 = (uint64_t)8387235364025352520;
    // EBPF_OP_STXDW pc=762 dst=r10 src=r1 offset=-80 imm=0
#line 298 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=763 dst=r1 src=r0 offset=0 imm=1380274271
#line 298 "sample/undocked/map.c"
    r1 = (uint64_t)6869485056696864863;
    // EBPF_OP_STXDW pc=765 dst=r10 src=r1 offset=-88 imm=0
#line 298 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=766 dst=r1 src=r0 offset=0 imm=1885433120
#line 298 "sample/undocked/map.c"
    r1 = (uint64_t)6148060143522245920;
    // EBPF_OP_STXDW pc=768 dst=r10 src=r1 offset=-96 imm=0
#line 298 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=769 dst=r1 src=r0 offset=0 imm=1279349317
#line 298 "sample/undocked/map.c"
    r1 = (uint64_t)8245921731643003461;
    // EBPF_OP_STXDW pc=771 dst=r10 src=r1 offset=-104 imm=0
#line 298 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=772 dst=r1 src=r0 offset=0 imm=1953719636
#line 298 "sample/undocked/map.c"
    r1 = (uint64_t)5639992313069659476;
    // EBPF_OP_STXDW pc=774 dst=r10 src=r1 offset=-112 imm=0
#line 298 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=775 dst=r3 src=r6 offset=0 imm=0
#line 298 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=776 dst=r3 src=r0 offset=0 imm=32
#line 298 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=777 dst=r3 src=r0 offset=0 imm=32
#line 298 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=778 dst=r1 src=r10 offset=0 imm=0
#line 298 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=779 dst=r1 src=r0 offset=0 imm=-112
#line 298 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=780 dst=r2 src=r0 offset=0 imm=49
#line 298 "sample/undocked/map.c"
    r2 = IMMEDIATE(49);
    // EBPF_OP_JA pc=781 dst=r0 src=r0 offset=-681 imm=0
#line 298 "sample/undocked/map.c"
    goto label_8;
label_51:
    // EBPF_OP_MOV64_REG pc=782 dst=r2 src=r10 offset=0 imm=0
#line 298 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=783 dst=r2 src=r0 offset=0 imm=-4
#line 92 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=784 dst=r3 src=r10 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=785 dst=r3 src=r0 offset=0 imm=-8
#line 92 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=786 dst=r1 src=r1 offset=0 imm=6
#line 92 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[5].address);
    // EBPF_OP_MOV64_IMM pc=788 dst=r4 src=r0 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=789 dst=r0 src=r0 offset=0 imm=2
#line 92 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 92 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 92 "sample/undocked/map.c"
        return 0;
#line 92 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=790 dst=r6 src=r0 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=791 dst=r3 src=r6 offset=0 imm=0
#line 92 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=792 dst=r3 src=r0 offset=0 imm=32
#line 92 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=793 dst=r3 src=r0 offset=0 imm=32
#line 92 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=794 dst=r3 src=r0 offset=1 imm=-1
#line 93 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 93 "sample/undocked/map.c"
        goto label_52;
#line 93 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=795 dst=r0 src=r0 offset=-103 imm=0
#line 93 "sample/undocked/map.c"
    goto label_45;
label_52:
    // EBPF_OP_MOV64_REG pc=796 dst=r2 src=r10 offset=0 imm=0
#line 93 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=797 dst=r2 src=r0 offset=0 imm=-4
#line 103 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=798 dst=r1 src=r1 offset=0 imm=6
#line 103 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[5].address);
    // EBPF_OP_CALL pc=800 dst=r0 src=r0 offset=0 imm=4
#line 103 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[5].address(r1, r2, r3, r4, r5, context);
#line 103 "sample/undocked/map.c"
    if ((runtime_context->helper_data[5].tail_call) && (r0 == 0)) {
#line 103 "sample/undocked/map.c"
        return 0;
#line 103 "sample/undocked/map.c"
    }
    // EBPF_OP_JNE_IMM pc=801 dst=r0 src=r0 offset=23 imm=0
#line 104 "sample/undocked/map.c"
    if (r0 != IMMEDIATE(0)) {
#line 104 "sample/undocked/map.c"
        goto label_53;
#line 104 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_IMM pc=802 dst=r1 src=r0 offset=0 imm=0
#line 104 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=803 dst=r10 src=r1 offset=-68 imm=0
#line 105 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-68)) = (uint8_t)r1;
    // EBPF_OP_MOV64_IMM pc=804 dst=r1 src=r0 offset=0 imm=1280070990
#line 105 "sample/undocked/map.c"
    r1 = IMMEDIATE(1280070990);
    // EBPF_OP_STXW pc=805 dst=r10 src=r1 offset=-72 imm=0
#line 105 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=806 dst=r1 src=r0 offset=0 imm=1920300133
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)2334102031925867621;
    // EBPF_OP_STXDW pc=808 dst=r10 src=r1 offset=-80 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=809 dst=r1 src=r0 offset=0 imm=1818582885
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)8223693201956233061;
    // EBPF_OP_STXDW pc=811 dst=r10 src=r1 offset=-88 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=812 dst=r1 src=r0 offset=0 imm=1683973230
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)8387229063778886766;
    // EBPF_OP_STXDW pc=814 dst=r10 src=r1 offset=-96 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=815 dst=r1 src=r0 offset=0 imm=1802465132
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)7016450394082471788;
    // EBPF_OP_STXDW pc=817 dst=r10 src=r1 offset=-104 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=818 dst=r1 src=r0 offset=0 imm=1600548962
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=820 dst=r10 src=r1 offset=-112 imm=0
#line 105 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=821 dst=r1 src=r10 offset=0 imm=0
#line 105 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=822 dst=r1 src=r0 offset=0 imm=-112
#line 105 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=823 dst=r2 src=r0 offset=0 imm=45
#line 105 "sample/undocked/map.c"
    r2 = IMMEDIATE(45);
    // EBPF_OP_JA pc=824 dst=r0 src=r0 offset=-100 imm=0
#line 105 "sample/undocked/map.c"
    goto label_47;
label_53:
    // EBPF_OP_MOV64_IMM pc=825 dst=r1 src=r0 offset=0 imm=0
#line 105 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=826 dst=r10 src=r1 offset=-4 imm=0
#line 114 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_IMM pc=827 dst=r7 src=r0 offset=0 imm=1
#line 114 "sample/undocked/map.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=828 dst=r10 src=r7 offset=-8 imm=0
#line 115 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=829 dst=r2 src=r10 offset=0 imm=0
#line 115 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=830 dst=r2 src=r0 offset=0 imm=-4
#line 115 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=831 dst=r3 src=r10 offset=0 imm=0
#line 115 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=832 dst=r3 src=r0 offset=0 imm=-8
#line 115 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=833 dst=r1 src=r1 offset=0 imm=5
#line 129 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[4].address);
    // EBPF_OP_MOV64_IMM pc=835 dst=r4 src=r0 offset=0 imm=0
#line 129 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=836 dst=r0 src=r0 offset=0 imm=2
#line 129 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 129 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 129 "sample/undocked/map.c"
        return 0;
#line 129 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=837 dst=r6 src=r0 offset=0 imm=0
#line 129 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=838 dst=r3 src=r6 offset=0 imm=0
#line 129 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=839 dst=r3 src=r0 offset=0 imm=32
#line 129 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=840 dst=r3 src=r0 offset=0 imm=32
#line 129 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=841 dst=r3 src=r0 offset=1 imm=-1
#line 130 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 130 "sample/undocked/map.c"
        goto label_54;
#line 130 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=842 dst=r0 src=r0 offset=159 imm=0
#line 130 "sample/undocked/map.c"
    goto label_64;
label_54:
    // EBPF_OP_STXW pc=843 dst=r10 src=r7 offset=-4 imm=0
#line 134 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=844 dst=r2 src=r10 offset=0 imm=0
#line 134 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=845 dst=r2 src=r0 offset=0 imm=-4
#line 134 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=846 dst=r3 src=r10 offset=0 imm=0
#line 134 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=847 dst=r3 src=r0 offset=0 imm=-8
#line 134 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=848 dst=r1 src=r1 offset=0 imm=5
#line 135 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[4].address);
    // EBPF_OP_MOV64_IMM pc=850 dst=r4 src=r0 offset=0 imm=0
#line 135 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=851 dst=r0 src=r0 offset=0 imm=2
#line 135 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 135 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 135 "sample/undocked/map.c"
        return 0;
#line 135 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=852 dst=r6 src=r0 offset=0 imm=0
#line 135 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=853 dst=r3 src=r6 offset=0 imm=0
#line 135 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=854 dst=r3 src=r0 offset=0 imm=32
#line 135 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=855 dst=r3 src=r0 offset=0 imm=32
#line 135 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=856 dst=r3 src=r0 offset=1 imm=-1
#line 136 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 136 "sample/undocked/map.c"
        goto label_55;
#line 136 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=857 dst=r0 src=r0 offset=144 imm=0
#line 136 "sample/undocked/map.c"
    goto label_64;
label_55:
    // EBPF_OP_MOV64_IMM pc=858 dst=r1 src=r0 offset=0 imm=2
#line 136 "sample/undocked/map.c"
    r1 = IMMEDIATE(2);
    // EBPF_OP_STXW pc=859 dst=r10 src=r1 offset=-4 imm=0
#line 140 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=860 dst=r2 src=r10 offset=0 imm=0
#line 140 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=861 dst=r2 src=r0 offset=0 imm=-4
#line 140 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=862 dst=r3 src=r10 offset=0 imm=0
#line 140 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=863 dst=r3 src=r0 offset=0 imm=-8
#line 140 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=864 dst=r1 src=r1 offset=0 imm=5
#line 141 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[4].address);
    // EBPF_OP_MOV64_IMM pc=866 dst=r4 src=r0 offset=0 imm=0
#line 141 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=867 dst=r0 src=r0 offset=0 imm=2
#line 141 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 141 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 141 "sample/undocked/map.c"
        return 0;
#line 141 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=868 dst=r6 src=r0 offset=0 imm=0
#line 141 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=869 dst=r3 src=r6 offset=0 imm=0
#line 141 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=870 dst=r3 src=r0 offset=0 imm=32
#line 141 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=871 dst=r3 src=r0 offset=0 imm=32
#line 141 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=872 dst=r3 src=r0 offset=1 imm=-1
#line 142 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 142 "sample/undocked/map.c"
        goto label_56;
#line 142 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=873 dst=r0 src=r0 offset=128 imm=0
#line 142 "sample/undocked/map.c"
    goto label_64;
label_56:
    // EBPF_OP_MOV64_IMM pc=874 dst=r1 src=r0 offset=0 imm=3
#line 142 "sample/undocked/map.c"
    r1 = IMMEDIATE(3);
    // EBPF_OP_STXW pc=875 dst=r10 src=r1 offset=-4 imm=0
#line 146 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=876 dst=r2 src=r10 offset=0 imm=0
#line 146 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=877 dst=r2 src=r0 offset=0 imm=-4
#line 146 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=878 dst=r3 src=r10 offset=0 imm=0
#line 146 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=879 dst=r3 src=r0 offset=0 imm=-8
#line 146 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=880 dst=r1 src=r1 offset=0 imm=5
#line 147 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[4].address);
    // EBPF_OP_MOV64_IMM pc=882 dst=r4 src=r0 offset=0 imm=0
#line 147 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=883 dst=r0 src=r0 offset=0 imm=2
#line 147 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 147 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 147 "sample/undocked/map.c"
        return 0;
#line 147 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=884 dst=r6 src=r0 offset=0 imm=0
#line 147 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=885 dst=r3 src=r6 offset=0 imm=0
#line 147 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=886 dst=r3 src=r0 offset=0 imm=32
#line 147 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=887 dst=r3 src=r0 offset=0 imm=32
#line 147 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=888 dst=r3 src=r0 offset=1 imm=-1
#line 148 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 148 "sample/undocked/map.c"
        goto label_57;
#line 148 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=889 dst=r0 src=r0 offset=112 imm=0
#line 148 "sample/undocked/map.c"
    goto label_64;
label_57:
    // EBPF_OP_MOV64_IMM pc=890 dst=r1 src=r0 offset=0 imm=4
#line 148 "sample/undocked/map.c"
    r1 = IMMEDIATE(4);
    // EBPF_OP_STXW pc=891 dst=r10 src=r1 offset=-4 imm=0
#line 152 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=892 dst=r2 src=r10 offset=0 imm=0
#line 152 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=893 dst=r2 src=r0 offset=0 imm=-4
#line 152 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=894 dst=r3 src=r10 offset=0 imm=0
#line 152 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=895 dst=r3 src=r0 offset=0 imm=-8
#line 152 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=896 dst=r1 src=r1 offset=0 imm=5
#line 153 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[4].address);
    // EBPF_OP_MOV64_IMM pc=898 dst=r4 src=r0 offset=0 imm=0
#line 153 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=899 dst=r0 src=r0 offset=0 imm=2
#line 153 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 153 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 153 "sample/undocked/map.c"
        return 0;
#line 153 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=900 dst=r6 src=r0 offset=0 imm=0
#line 153 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=901 dst=r3 src=r6 offset=0 imm=0
#line 153 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=902 dst=r3 src=r0 offset=0 imm=32
#line 153 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=903 dst=r3 src=r0 offset=0 imm=32
#line 153 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=904 dst=r3 src=r0 offset=1 imm=-1
#line 154 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 154 "sample/undocked/map.c"
        goto label_58;
#line 154 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=905 dst=r0 src=r0 offset=96 imm=0
#line 154 "sample/undocked/map.c"
    goto label_64;
label_58:
    // EBPF_OP_MOV64_IMM pc=906 dst=r1 src=r0 offset=0 imm=5
#line 154 "sample/undocked/map.c"
    r1 = IMMEDIATE(5);
    // EBPF_OP_STXW pc=907 dst=r10 src=r1 offset=-4 imm=0
#line 158 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=908 dst=r2 src=r10 offset=0 imm=0
#line 158 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=909 dst=r2 src=r0 offset=0 imm=-4
#line 158 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=910 dst=r3 src=r10 offset=0 imm=0
#line 158 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=911 dst=r3 src=r0 offset=0 imm=-8
#line 158 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=912 dst=r1 src=r1 offset=0 imm=5
#line 159 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[4].address);
    // EBPF_OP_MOV64_IMM pc=914 dst=r4 src=r0 offset=0 imm=0
#line 159 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=915 dst=r0 src=r0 offset=0 imm=2
#line 159 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 159 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 159 "sample/undocked/map.c"
        return 0;
#line 159 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=916 dst=r6 src=r0 offset=0 imm=0
#line 159 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=917 dst=r3 src=r6 offset=0 imm=0
#line 159 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=918 dst=r3 src=r0 offset=0 imm=32
#line 159 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=919 dst=r3 src=r0 offset=0 imm=32
#line 159 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=920 dst=r3 src=r0 offset=1 imm=-1
#line 160 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 160 "sample/undocked/map.c"
        goto label_59;
#line 160 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=921 dst=r0 src=r0 offset=80 imm=0
#line 160 "sample/undocked/map.c"
    goto label_64;
label_59:
    // EBPF_OP_MOV64_IMM pc=922 dst=r1 src=r0 offset=0 imm=6
#line 160 "sample/undocked/map.c"
    r1 = IMMEDIATE(6);
    // EBPF_OP_STXW pc=923 dst=r10 src=r1 offset=-4 imm=0
#line 164 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=924 dst=r2 src=r10 offset=0 imm=0
#line 164 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=925 dst=r2 src=r0 offset=0 imm=-4
#line 164 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=926 dst=r3 src=r10 offset=0 imm=0
#line 164 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=927 dst=r3 src=r0 offset=0 imm=-8
#line 164 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=928 dst=r1 src=r1 offset=0 imm=5
#line 165 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[4].address);
    // EBPF_OP_MOV64_IMM pc=930 dst=r4 src=r0 offset=0 imm=0
#line 165 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=931 dst=r0 src=r0 offset=0 imm=2
#line 165 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 165 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 165 "sample/undocked/map.c"
        return 0;
#line 165 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=932 dst=r6 src=r0 offset=0 imm=0
#line 165 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=933 dst=r3 src=r6 offset=0 imm=0
#line 165 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=934 dst=r3 src=r0 offset=0 imm=32
#line 165 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=935 dst=r3 src=r0 offset=0 imm=32
#line 165 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=936 dst=r3 src=r0 offset=1 imm=-1
#line 166 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 166 "sample/undocked/map.c"
        goto label_60;
#line 166 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=937 dst=r0 src=r0 offset=64 imm=0
#line 166 "sample/undocked/map.c"
    goto label_64;
label_60:
    // EBPF_OP_MOV64_IMM pc=938 dst=r1 src=r0 offset=0 imm=7
#line 166 "sample/undocked/map.c"
    r1 = IMMEDIATE(7);
    // EBPF_OP_STXW pc=939 dst=r10 src=r1 offset=-4 imm=0
#line 170 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=940 dst=r2 src=r10 offset=0 imm=0
#line 170 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=941 dst=r2 src=r0 offset=0 imm=-4
#line 170 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=942 dst=r3 src=r10 offset=0 imm=0
#line 170 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=943 dst=r3 src=r0 offset=0 imm=-8
#line 170 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=944 dst=r1 src=r1 offset=0 imm=5
#line 171 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[4].address);
    // EBPF_OP_MOV64_IMM pc=946 dst=r4 src=r0 offset=0 imm=0
#line 171 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=947 dst=r0 src=r0 offset=0 imm=2
#line 171 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 171 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 171 "sample/undocked/map.c"
        return 0;
#line 171 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=948 dst=r6 src=r0 offset=0 imm=0
#line 171 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=949 dst=r3 src=r6 offset=0 imm=0
#line 171 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=950 dst=r3 src=r0 offset=0 imm=32
#line 171 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=951 dst=r3 src=r0 offset=0 imm=32
#line 171 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=952 dst=r3 src=r0 offset=1 imm=-1
#line 172 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 172 "sample/undocked/map.c"
        goto label_61;
#line 172 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=953 dst=r0 src=r0 offset=48 imm=0
#line 172 "sample/undocked/map.c"
    goto label_64;
label_61:
    // EBPF_OP_MOV64_IMM pc=954 dst=r1 src=r0 offset=0 imm=8
#line 172 "sample/undocked/map.c"
    r1 = IMMEDIATE(8);
    // EBPF_OP_STXW pc=955 dst=r10 src=r1 offset=-4 imm=0
#line 176 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=956 dst=r2 src=r10 offset=0 imm=0
#line 176 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=957 dst=r2 src=r0 offset=0 imm=-4
#line 176 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=958 dst=r3 src=r10 offset=0 imm=0
#line 176 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=959 dst=r3 src=r0 offset=0 imm=-8
#line 176 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=960 dst=r1 src=r1 offset=0 imm=5
#line 177 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[4].address);
    // EBPF_OP_MOV64_IMM pc=962 dst=r4 src=r0 offset=0 imm=0
#line 177 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=963 dst=r0 src=r0 offset=0 imm=2
#line 177 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 177 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 177 "sample/undocked/map.c"
        return 0;
#line 177 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=964 dst=r6 src=r0 offset=0 imm=0
#line 177 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=965 dst=r3 src=r6 offset=0 imm=0
#line 177 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=966 dst=r3 src=r0 offset=0 imm=32
#line 177 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=967 dst=r3 src=r0 offset=0 imm=32
#line 177 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=968 dst=r3 src=r0 offset=1 imm=-1
#line 178 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 178 "sample/undocked/map.c"
        goto label_62;
#line 178 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=969 dst=r0 src=r0 offset=32 imm=0
#line 178 "sample/undocked/map.c"
    goto label_64;
label_62:
    // EBPF_OP_MOV64_IMM pc=970 dst=r1 src=r0 offset=0 imm=9
#line 178 "sample/undocked/map.c"
    r1 = IMMEDIATE(9);
    // EBPF_OP_STXW pc=971 dst=r10 src=r1 offset=-4 imm=0
#line 182 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=972 dst=r2 src=r10 offset=0 imm=0
#line 182 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=973 dst=r2 src=r0 offset=0 imm=-4
#line 182 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=974 dst=r3 src=r10 offset=0 imm=0
#line 182 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=975 dst=r3 src=r0 offset=0 imm=-8
#line 182 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=976 dst=r1 src=r1 offset=0 imm=5
#line 183 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[4].address);
    // EBPF_OP_MOV64_IMM pc=978 dst=r4 src=r0 offset=0 imm=0
#line 183 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=979 dst=r0 src=r0 offset=0 imm=2
#line 183 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 183 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 183 "sample/undocked/map.c"
        return 0;
#line 183 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=980 dst=r6 src=r0 offset=0 imm=0
#line 183 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=981 dst=r3 src=r6 offset=0 imm=0
#line 183 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=982 dst=r3 src=r0 offset=0 imm=32
#line 183 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=983 dst=r3 src=r0 offset=0 imm=32
#line 183 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=984 dst=r3 src=r0 offset=1 imm=-1
#line 184 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 184 "sample/undocked/map.c"
        goto label_63;
#line 184 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=985 dst=r0 src=r0 offset=16 imm=0
#line 184 "sample/undocked/map.c"
    goto label_64;
label_63:
    // EBPF_OP_MOV64_IMM pc=986 dst=r1 src=r0 offset=0 imm=10
#line 184 "sample/undocked/map.c"
    r1 = IMMEDIATE(10);
    // EBPF_OP_STXW pc=987 dst=r10 src=r1 offset=-4 imm=0
#line 188 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=988 dst=r2 src=r10 offset=0 imm=0
#line 188 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=989 dst=r2 src=r0 offset=0 imm=-4
#line 188 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=990 dst=r3 src=r10 offset=0 imm=0
#line 188 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=991 dst=r3 src=r0 offset=0 imm=-8
#line 188 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_IMM pc=992 dst=r7 src=r0 offset=0 imm=0
#line 188 "sample/undocked/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=993 dst=r1 src=r1 offset=0 imm=5
#line 189 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[4].address);
    // EBPF_OP_MOV64_IMM pc=995 dst=r4 src=r0 offset=0 imm=0
#line 189 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=996 dst=r0 src=r0 offset=0 imm=2
#line 189 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 189 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 189 "sample/undocked/map.c"
        return 0;
#line 189 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=997 dst=r6 src=r0 offset=0 imm=0
#line 189 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=998 dst=r3 src=r6 offset=0 imm=0
#line 189 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=999 dst=r3 src=r0 offset=0 imm=32
#line 189 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1000 dst=r3 src=r0 offset=0 imm=32
#line 189 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=1001 dst=r3 src=r0 offset=32 imm=-1
#line 190 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 190 "sample/undocked/map.c"
        goto label_65;
#line 190 "sample/undocked/map.c"
    }
label_64:
    // EBPF_OP_LDDW pc=1002 dst=r1 src=r0 offset=0 imm=1684369010
#line 190 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=1004 dst=r10 src=r1 offset=-88 imm=0
#line 190 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1005 dst=r1 src=r0 offset=0 imm=544040300
#line 190 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=1007 dst=r10 src=r1 offset=-96 imm=0
#line 190 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1008 dst=r1 src=r0 offset=0 imm=1633972341
#line 190 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671142817909;
    // EBPF_OP_STXDW pc=1010 dst=r10 src=r1 offset=-104 imm=0
#line 190 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1011 dst=r1 src=r0 offset=0 imm=1600548962
#line 190 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1013 dst=r10 src=r1 offset=-112 imm=0
#line 190 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1014 dst=r1 src=r10 offset=0 imm=0
#line 190 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1015 dst=r1 src=r0 offset=0 imm=-112
#line 190 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=1016 dst=r2 src=r0 offset=0 imm=32
#line 190 "sample/undocked/map.c"
    r2 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=1017 dst=r0 src=r0 offset=0 imm=13
#line 190 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 190 "sample/undocked/map.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 190 "sample/undocked/map.c"
        return 0;
#line 190 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_IMM pc=1018 dst=r1 src=r0 offset=0 imm=100
#line 190 "sample/undocked/map.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXH pc=1019 dst=r10 src=r1 offset=-76 imm=0
#line 300 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-76)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=1020 dst=r1 src=r0 offset=0 imm=622879845
#line 300 "sample/undocked/map.c"
    r1 = IMMEDIATE(622879845);
    // EBPF_OP_STXW pc=1021 dst=r10 src=r1 offset=-80 imm=0
#line 300 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=1022 dst=r1 src=r0 offset=0 imm=1701978184
#line 300 "sample/undocked/map.c"
    r1 = (uint64_t)7958552634295722056;
    // EBPF_OP_STXDW pc=1024 dst=r10 src=r1 offset=-88 imm=0
#line 300 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1025 dst=r1 src=r0 offset=0 imm=1431456800
#line 300 "sample/undocked/map.c"
    r1 = (uint64_t)5999155752924761120;
    // EBPF_OP_STXDW pc=1027 dst=r10 src=r1 offset=-96 imm=0
#line 300 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1028 dst=r1 src=r0 offset=0 imm=1919903264
#line 300 "sample/undocked/map.c"
    r1 = (uint64_t)8097873591115146784;
    // EBPF_OP_STXDW pc=1030 dst=r10 src=r1 offset=-104 imm=0
#line 300 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1031 dst=r1 src=r0 offset=0 imm=1953719636
#line 300 "sample/undocked/map.c"
    r1 = (uint64_t)6148060143590532436;
    // EBPF_OP_JA pc=1033 dst=r0 src=r0 offset=-940 imm=0
#line 300 "sample/undocked/map.c"
    goto label_7;
label_65:
    // EBPF_OP_STXW pc=1034 dst=r10 src=r7 offset=-4 imm=0
#line 114 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_IMM pc=1035 dst=r7 src=r0 offset=0 imm=1
#line 114 "sample/undocked/map.c"
    r7 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=1036 dst=r10 src=r7 offset=-8 imm=0
#line 115 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=1037 dst=r2 src=r10 offset=0 imm=0
#line 115 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1038 dst=r2 src=r0 offset=0 imm=-4
#line 115 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=1039 dst=r3 src=r10 offset=0 imm=0
#line 115 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=1040 dst=r3 src=r0 offset=0 imm=-8
#line 115 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=1041 dst=r1 src=r1 offset=0 imm=6
#line 129 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[5].address);
    // EBPF_OP_MOV64_IMM pc=1043 dst=r4 src=r0 offset=0 imm=0
#line 129 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1044 dst=r0 src=r0 offset=0 imm=2
#line 129 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 129 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 129 "sample/undocked/map.c"
        return 0;
#line 129 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1045 dst=r6 src=r0 offset=0 imm=0
#line 129 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1046 dst=r3 src=r6 offset=0 imm=0
#line 129 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=1047 dst=r3 src=r0 offset=0 imm=32
#line 129 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1048 dst=r3 src=r0 offset=0 imm=32
#line 129 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=1049 dst=r3 src=r0 offset=1 imm=-1
#line 130 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 130 "sample/undocked/map.c"
        goto label_66;
#line 130 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1050 dst=r0 src=r0 offset=159 imm=0
#line 130 "sample/undocked/map.c"
    goto label_76;
label_66:
    // EBPF_OP_STXW pc=1051 dst=r10 src=r7 offset=-4 imm=0
#line 134 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=1052 dst=r2 src=r10 offset=0 imm=0
#line 134 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1053 dst=r2 src=r0 offset=0 imm=-4
#line 134 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=1054 dst=r3 src=r10 offset=0 imm=0
#line 134 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=1055 dst=r3 src=r0 offset=0 imm=-8
#line 134 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=1056 dst=r1 src=r1 offset=0 imm=6
#line 135 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[5].address);
    // EBPF_OP_MOV64_IMM pc=1058 dst=r4 src=r0 offset=0 imm=0
#line 135 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1059 dst=r0 src=r0 offset=0 imm=2
#line 135 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 135 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 135 "sample/undocked/map.c"
        return 0;
#line 135 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1060 dst=r6 src=r0 offset=0 imm=0
#line 135 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1061 dst=r3 src=r6 offset=0 imm=0
#line 135 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=1062 dst=r3 src=r0 offset=0 imm=32
#line 135 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1063 dst=r3 src=r0 offset=0 imm=32
#line 135 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=1064 dst=r3 src=r0 offset=1 imm=-1
#line 136 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 136 "sample/undocked/map.c"
        goto label_67;
#line 136 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1065 dst=r0 src=r0 offset=144 imm=0
#line 136 "sample/undocked/map.c"
    goto label_76;
label_67:
    // EBPF_OP_MOV64_IMM pc=1066 dst=r1 src=r0 offset=0 imm=2
#line 136 "sample/undocked/map.c"
    r1 = IMMEDIATE(2);
    // EBPF_OP_STXW pc=1067 dst=r10 src=r1 offset=-4 imm=0
#line 140 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1068 dst=r2 src=r10 offset=0 imm=0
#line 140 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1069 dst=r2 src=r0 offset=0 imm=-4
#line 140 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=1070 dst=r3 src=r10 offset=0 imm=0
#line 140 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=1071 dst=r3 src=r0 offset=0 imm=-8
#line 140 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=1072 dst=r1 src=r1 offset=0 imm=6
#line 141 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[5].address);
    // EBPF_OP_MOV64_IMM pc=1074 dst=r4 src=r0 offset=0 imm=0
#line 141 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1075 dst=r0 src=r0 offset=0 imm=2
#line 141 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 141 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 141 "sample/undocked/map.c"
        return 0;
#line 141 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1076 dst=r6 src=r0 offset=0 imm=0
#line 141 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1077 dst=r3 src=r6 offset=0 imm=0
#line 141 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=1078 dst=r3 src=r0 offset=0 imm=32
#line 141 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1079 dst=r3 src=r0 offset=0 imm=32
#line 141 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=1080 dst=r3 src=r0 offset=1 imm=-1
#line 142 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 142 "sample/undocked/map.c"
        goto label_68;
#line 142 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1081 dst=r0 src=r0 offset=128 imm=0
#line 142 "sample/undocked/map.c"
    goto label_76;
label_68:
    // EBPF_OP_MOV64_IMM pc=1082 dst=r1 src=r0 offset=0 imm=3
#line 142 "sample/undocked/map.c"
    r1 = IMMEDIATE(3);
    // EBPF_OP_STXW pc=1083 dst=r10 src=r1 offset=-4 imm=0
#line 146 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1084 dst=r2 src=r10 offset=0 imm=0
#line 146 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1085 dst=r2 src=r0 offset=0 imm=-4
#line 146 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=1086 dst=r3 src=r10 offset=0 imm=0
#line 146 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=1087 dst=r3 src=r0 offset=0 imm=-8
#line 146 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=1088 dst=r1 src=r1 offset=0 imm=6
#line 147 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[5].address);
    // EBPF_OP_MOV64_IMM pc=1090 dst=r4 src=r0 offset=0 imm=0
#line 147 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1091 dst=r0 src=r0 offset=0 imm=2
#line 147 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 147 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 147 "sample/undocked/map.c"
        return 0;
#line 147 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1092 dst=r6 src=r0 offset=0 imm=0
#line 147 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1093 dst=r3 src=r6 offset=0 imm=0
#line 147 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=1094 dst=r3 src=r0 offset=0 imm=32
#line 147 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1095 dst=r3 src=r0 offset=0 imm=32
#line 147 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=1096 dst=r3 src=r0 offset=1 imm=-1
#line 148 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 148 "sample/undocked/map.c"
        goto label_69;
#line 148 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1097 dst=r0 src=r0 offset=112 imm=0
#line 148 "sample/undocked/map.c"
    goto label_76;
label_69:
    // EBPF_OP_MOV64_IMM pc=1098 dst=r1 src=r0 offset=0 imm=4
#line 148 "sample/undocked/map.c"
    r1 = IMMEDIATE(4);
    // EBPF_OP_STXW pc=1099 dst=r10 src=r1 offset=-4 imm=0
#line 152 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1100 dst=r2 src=r10 offset=0 imm=0
#line 152 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1101 dst=r2 src=r0 offset=0 imm=-4
#line 152 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=1102 dst=r3 src=r10 offset=0 imm=0
#line 152 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=1103 dst=r3 src=r0 offset=0 imm=-8
#line 152 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=1104 dst=r1 src=r1 offset=0 imm=6
#line 153 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[5].address);
    // EBPF_OP_MOV64_IMM pc=1106 dst=r4 src=r0 offset=0 imm=0
#line 153 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1107 dst=r0 src=r0 offset=0 imm=2
#line 153 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 153 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 153 "sample/undocked/map.c"
        return 0;
#line 153 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1108 dst=r6 src=r0 offset=0 imm=0
#line 153 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1109 dst=r3 src=r6 offset=0 imm=0
#line 153 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=1110 dst=r3 src=r0 offset=0 imm=32
#line 153 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1111 dst=r3 src=r0 offset=0 imm=32
#line 153 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=1112 dst=r3 src=r0 offset=1 imm=-1
#line 154 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 154 "sample/undocked/map.c"
        goto label_70;
#line 154 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1113 dst=r0 src=r0 offset=96 imm=0
#line 154 "sample/undocked/map.c"
    goto label_76;
label_70:
    // EBPF_OP_MOV64_IMM pc=1114 dst=r1 src=r0 offset=0 imm=5
#line 154 "sample/undocked/map.c"
    r1 = IMMEDIATE(5);
    // EBPF_OP_STXW pc=1115 dst=r10 src=r1 offset=-4 imm=0
#line 158 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1116 dst=r2 src=r10 offset=0 imm=0
#line 158 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1117 dst=r2 src=r0 offset=0 imm=-4
#line 158 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=1118 dst=r3 src=r10 offset=0 imm=0
#line 158 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=1119 dst=r3 src=r0 offset=0 imm=-8
#line 158 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=1120 dst=r1 src=r1 offset=0 imm=6
#line 159 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[5].address);
    // EBPF_OP_MOV64_IMM pc=1122 dst=r4 src=r0 offset=0 imm=0
#line 159 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1123 dst=r0 src=r0 offset=0 imm=2
#line 159 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 159 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 159 "sample/undocked/map.c"
        return 0;
#line 159 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1124 dst=r6 src=r0 offset=0 imm=0
#line 159 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1125 dst=r3 src=r6 offset=0 imm=0
#line 159 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=1126 dst=r3 src=r0 offset=0 imm=32
#line 159 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1127 dst=r3 src=r0 offset=0 imm=32
#line 159 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=1128 dst=r3 src=r0 offset=1 imm=-1
#line 160 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 160 "sample/undocked/map.c"
        goto label_71;
#line 160 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1129 dst=r0 src=r0 offset=80 imm=0
#line 160 "sample/undocked/map.c"
    goto label_76;
label_71:
    // EBPF_OP_MOV64_IMM pc=1130 dst=r1 src=r0 offset=0 imm=6
#line 160 "sample/undocked/map.c"
    r1 = IMMEDIATE(6);
    // EBPF_OP_STXW pc=1131 dst=r10 src=r1 offset=-4 imm=0
#line 164 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1132 dst=r2 src=r10 offset=0 imm=0
#line 164 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1133 dst=r2 src=r0 offset=0 imm=-4
#line 164 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=1134 dst=r3 src=r10 offset=0 imm=0
#line 164 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=1135 dst=r3 src=r0 offset=0 imm=-8
#line 164 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=1136 dst=r1 src=r1 offset=0 imm=6
#line 165 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[5].address);
    // EBPF_OP_MOV64_IMM pc=1138 dst=r4 src=r0 offset=0 imm=0
#line 165 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1139 dst=r0 src=r0 offset=0 imm=2
#line 165 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 165 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 165 "sample/undocked/map.c"
        return 0;
#line 165 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1140 dst=r6 src=r0 offset=0 imm=0
#line 165 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1141 dst=r3 src=r6 offset=0 imm=0
#line 165 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=1142 dst=r3 src=r0 offset=0 imm=32
#line 165 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1143 dst=r3 src=r0 offset=0 imm=32
#line 165 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=1144 dst=r3 src=r0 offset=1 imm=-1
#line 166 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 166 "sample/undocked/map.c"
        goto label_72;
#line 166 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1145 dst=r0 src=r0 offset=64 imm=0
#line 166 "sample/undocked/map.c"
    goto label_76;
label_72:
    // EBPF_OP_MOV64_IMM pc=1146 dst=r1 src=r0 offset=0 imm=7
#line 166 "sample/undocked/map.c"
    r1 = IMMEDIATE(7);
    // EBPF_OP_STXW pc=1147 dst=r10 src=r1 offset=-4 imm=0
#line 170 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1148 dst=r2 src=r10 offset=0 imm=0
#line 170 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1149 dst=r2 src=r0 offset=0 imm=-4
#line 170 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=1150 dst=r3 src=r10 offset=0 imm=0
#line 170 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=1151 dst=r3 src=r0 offset=0 imm=-8
#line 170 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=1152 dst=r1 src=r1 offset=0 imm=6
#line 171 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[5].address);
    // EBPF_OP_MOV64_IMM pc=1154 dst=r4 src=r0 offset=0 imm=0
#line 171 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1155 dst=r0 src=r0 offset=0 imm=2
#line 171 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 171 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 171 "sample/undocked/map.c"
        return 0;
#line 171 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1156 dst=r6 src=r0 offset=0 imm=0
#line 171 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1157 dst=r3 src=r6 offset=0 imm=0
#line 171 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=1158 dst=r3 src=r0 offset=0 imm=32
#line 171 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1159 dst=r3 src=r0 offset=0 imm=32
#line 171 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=1160 dst=r3 src=r0 offset=1 imm=-1
#line 172 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 172 "sample/undocked/map.c"
        goto label_73;
#line 172 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1161 dst=r0 src=r0 offset=48 imm=0
#line 172 "sample/undocked/map.c"
    goto label_76;
label_73:
    // EBPF_OP_MOV64_IMM pc=1162 dst=r1 src=r0 offset=0 imm=8
#line 172 "sample/undocked/map.c"
    r1 = IMMEDIATE(8);
    // EBPF_OP_STXW pc=1163 dst=r10 src=r1 offset=-4 imm=0
#line 176 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1164 dst=r2 src=r10 offset=0 imm=0
#line 176 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1165 dst=r2 src=r0 offset=0 imm=-4
#line 176 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=1166 dst=r3 src=r10 offset=0 imm=0
#line 176 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=1167 dst=r3 src=r0 offset=0 imm=-8
#line 176 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=1168 dst=r1 src=r1 offset=0 imm=6
#line 177 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[5].address);
    // EBPF_OP_MOV64_IMM pc=1170 dst=r4 src=r0 offset=0 imm=0
#line 177 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1171 dst=r0 src=r0 offset=0 imm=2
#line 177 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 177 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 177 "sample/undocked/map.c"
        return 0;
#line 177 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1172 dst=r6 src=r0 offset=0 imm=0
#line 177 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1173 dst=r3 src=r6 offset=0 imm=0
#line 177 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=1174 dst=r3 src=r0 offset=0 imm=32
#line 177 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1175 dst=r3 src=r0 offset=0 imm=32
#line 177 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=1176 dst=r3 src=r0 offset=1 imm=-1
#line 178 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 178 "sample/undocked/map.c"
        goto label_74;
#line 178 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1177 dst=r0 src=r0 offset=32 imm=0
#line 178 "sample/undocked/map.c"
    goto label_76;
label_74:
    // EBPF_OP_MOV64_IMM pc=1178 dst=r1 src=r0 offset=0 imm=9
#line 178 "sample/undocked/map.c"
    r1 = IMMEDIATE(9);
    // EBPF_OP_STXW pc=1179 dst=r10 src=r1 offset=-4 imm=0
#line 182 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1180 dst=r2 src=r10 offset=0 imm=0
#line 182 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1181 dst=r2 src=r0 offset=0 imm=-4
#line 182 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=1182 dst=r3 src=r10 offset=0 imm=0
#line 182 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=1183 dst=r3 src=r0 offset=0 imm=-8
#line 182 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_LDDW pc=1184 dst=r1 src=r1 offset=0 imm=6
#line 183 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[5].address);
    // EBPF_OP_MOV64_IMM pc=1186 dst=r4 src=r0 offset=0 imm=0
#line 183 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1187 dst=r0 src=r0 offset=0 imm=2
#line 183 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 183 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 183 "sample/undocked/map.c"
        return 0;
#line 183 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1188 dst=r6 src=r0 offset=0 imm=0
#line 183 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1189 dst=r3 src=r6 offset=0 imm=0
#line 183 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=1190 dst=r3 src=r0 offset=0 imm=32
#line 183 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1191 dst=r3 src=r0 offset=0 imm=32
#line 183 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=1192 dst=r3 src=r0 offset=1 imm=-1
#line 184 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 184 "sample/undocked/map.c"
        goto label_75;
#line 184 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1193 dst=r0 src=r0 offset=16 imm=0
#line 184 "sample/undocked/map.c"
    goto label_76;
label_75:
    // EBPF_OP_MOV64_IMM pc=1194 dst=r1 src=r0 offset=0 imm=10
#line 184 "sample/undocked/map.c"
    r1 = IMMEDIATE(10);
    // EBPF_OP_STXW pc=1195 dst=r10 src=r1 offset=-4 imm=0
#line 188 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1196 dst=r2 src=r10 offset=0 imm=0
#line 188 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1197 dst=r2 src=r0 offset=0 imm=-4
#line 188 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_REG pc=1198 dst=r3 src=r10 offset=0 imm=0
#line 188 "sample/undocked/map.c"
    r3 = r10;
    // EBPF_OP_ADD64_IMM pc=1199 dst=r3 src=r0 offset=0 imm=-8
#line 188 "sample/undocked/map.c"
    r3 += IMMEDIATE(-8);
    // EBPF_OP_MOV64_IMM pc=1200 dst=r7 src=r0 offset=0 imm=0
#line 188 "sample/undocked/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=1201 dst=r1 src=r1 offset=0 imm=6
#line 189 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[5].address);
    // EBPF_OP_MOV64_IMM pc=1203 dst=r4 src=r0 offset=0 imm=0
#line 189 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1204 dst=r0 src=r0 offset=0 imm=2
#line 189 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 189 "sample/undocked/map.c"
    if ((runtime_context->helper_data[0].tail_call) && (r0 == 0)) {
#line 189 "sample/undocked/map.c"
        return 0;
#line 189 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1205 dst=r6 src=r0 offset=0 imm=0
#line 189 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1206 dst=r3 src=r6 offset=0 imm=0
#line 189 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=1207 dst=r3 src=r0 offset=0 imm=32
#line 189 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1208 dst=r3 src=r0 offset=0 imm=32
#line 189 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=1209 dst=r3 src=r0 offset=35 imm=-1
#line 190 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 190 "sample/undocked/map.c"
        goto label_77;
#line 190 "sample/undocked/map.c"
    }
label_76:
    // EBPF_OP_LDDW pc=1210 dst=r1 src=r0 offset=0 imm=1684369010
#line 190 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=1212 dst=r10 src=r1 offset=-88 imm=0
#line 190 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1213 dst=r1 src=r0 offset=0 imm=544040300
#line 190 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
    // EBPF_OP_STXDW pc=1215 dst=r10 src=r1 offset=-96 imm=0
#line 190 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1216 dst=r1 src=r0 offset=0 imm=1633972341
#line 190 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671142817909;
    // EBPF_OP_STXDW pc=1218 dst=r10 src=r1 offset=-104 imm=0
#line 190 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1219 dst=r1 src=r0 offset=0 imm=1600548962
#line 190 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1221 dst=r10 src=r1 offset=-112 imm=0
#line 190 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1222 dst=r1 src=r10 offset=0 imm=0
#line 190 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1223 dst=r1 src=r0 offset=0 imm=-112
#line 190 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=1224 dst=r2 src=r0 offset=0 imm=32
#line 190 "sample/undocked/map.c"
    r2 = IMMEDIATE(32);
    // EBPF_OP_CALL pc=1225 dst=r0 src=r0 offset=0 imm=13
#line 190 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 190 "sample/undocked/map.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 190 "sample/undocked/map.c"
        return 0;
#line 190 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_IMM pc=1226 dst=r1 src=r0 offset=0 imm=0
#line 190 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=1227 dst=r10 src=r1 offset=-68 imm=0
#line 301 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-68)) = (uint8_t)r1;
    // EBPF_OP_MOV64_IMM pc=1228 dst=r1 src=r0 offset=0 imm=1680154724
#line 301 "sample/undocked/map.c"
    r1 = IMMEDIATE(1680154724);
    // EBPF_OP_STXW pc=1229 dst=r10 src=r1 offset=-72 imm=0
#line 301 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=1230 dst=r1 src=r0 offset=0 imm=1952805408
#line 301 "sample/undocked/map.c"
    r1 = (uint64_t)7308905094058439200;
    // EBPF_OP_STXDW pc=1232 dst=r10 src=r1 offset=-80 imm=0
#line 301 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1233 dst=r1 src=r0 offset=0 imm=1599426627
#line 301 "sample/undocked/map.c"
    r1 = (uint64_t)5211580972890673219;
    // EBPF_OP_STXDW pc=1235 dst=r10 src=r1 offset=-88 imm=0
#line 301 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1236 dst=r1 src=r0 offset=0 imm=1431456800
#line 301 "sample/undocked/map.c"
    r1 = (uint64_t)5928232854886698016;
    // EBPF_OP_STXDW pc=1238 dst=r10 src=r1 offset=-96 imm=0
#line 301 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1239 dst=r1 src=r0 offset=0 imm=1919903264
#line 301 "sample/undocked/map.c"
    r1 = (uint64_t)8097873591115146784;
    // EBPF_OP_STXDW pc=1241 dst=r10 src=r1 offset=-104 imm=0
#line 301 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1242 dst=r1 src=r0 offset=0 imm=1953719636
#line 301 "sample/undocked/map.c"
    r1 = (uint64_t)6148060143590532436;
    // EBPF_OP_JA pc=1244 dst=r0 src=r0 offset=-1001 imm=0
#line 301 "sample/undocked/map.c"
    goto label_19;
label_77:
    // EBPF_OP_STXW pc=1245 dst=r10 src=r7 offset=-4 imm=0
#line 240 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=1246 dst=r2 src=r10 offset=0 imm=0
#line 240 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1247 dst=r2 src=r0 offset=0 imm=-4
#line 240 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1248 dst=r1 src=r1 offset=0 imm=7
#line 240 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
    // EBPF_OP_CALL pc=1250 dst=r0 src=r0 offset=0 imm=18
#line 240 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[6].address(r1, r2, r3, r4, r5, context);
#line 240 "sample/undocked/map.c"
    if ((runtime_context->helper_data[6].tail_call) && (r0 == 0)) {
#line 240 "sample/undocked/map.c"
        return 0;
#line 240 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1251 dst=r6 src=r0 offset=0 imm=0
#line 240 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1252 dst=r4 src=r6 offset=0 imm=0
#line 240 "sample/undocked/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=1253 dst=r4 src=r0 offset=0 imm=32
#line 240 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1254 dst=r1 src=r4 offset=0 imm=0
#line 240 "sample/undocked/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=1255 dst=r1 src=r0 offset=0 imm=32
#line 240 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_LDDW pc=1256 dst=r2 src=r0 offset=0 imm=-7
#line 240 "sample/undocked/map.c"
    r2 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=1258 dst=r1 src=r2 offset=27 imm=0
#line 240 "sample/undocked/map.c"
    if (r1 == r2) {
#line 240 "sample/undocked/map.c"
        goto label_80;
#line 240 "sample/undocked/map.c"
    }
label_78:
    // EBPF_OP_MOV64_IMM pc=1259 dst=r1 src=r0 offset=0 imm=100
#line 240 "sample/undocked/map.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXH pc=1260 dst=r10 src=r1 offset=-64 imm=0
#line 240 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=1261 dst=r1 src=r0 offset=0 imm=1852994932
#line 240 "sample/undocked/map.c"
    r1 = (uint64_t)2675248565465544052;
    // EBPF_OP_STXDW pc=1263 dst=r10 src=r1 offset=-72 imm=0
#line 240 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1264 dst=r1 src=r0 offset=0 imm=622883948
#line 240 "sample/undocked/map.c"
    r1 = (uint64_t)7309940759667438700;
    // EBPF_OP_STXDW pc=1266 dst=r10 src=r1 offset=-80 imm=0
#line 240 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1267 dst=r1 src=r0 offset=0 imm=543649385
#line 240 "sample/undocked/map.c"
    r1 = (uint64_t)8463219665603620457;
    // EBPF_OP_STXDW pc=1269 dst=r10 src=r1 offset=-88 imm=0
#line 240 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1270 dst=r1 src=r0 offset=0 imm=2019893357
#line 240 "sample/undocked/map.c"
    r1 = (uint64_t)8386658464824631405;
    // EBPF_OP_STXDW pc=1272 dst=r10 src=r1 offset=-96 imm=0
#line 240 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1273 dst=r1 src=r0 offset=0 imm=1801807216
#line 240 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=1275 dst=r10 src=r1 offset=-104 imm=0
#line 240 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1276 dst=r1 src=r0 offset=0 imm=1600548962
#line 240 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1278 dst=r10 src=r1 offset=-112 imm=0
#line 240 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_ARSH64_IMM pc=1279 dst=r4 src=r0 offset=0 imm=32
#line 240 "sample/undocked/map.c"
    r4 = (int64_t)r4 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1280 dst=r1 src=r10 offset=0 imm=0
#line 240 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1281 dst=r1 src=r0 offset=0 imm=-112
#line 240 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=1282 dst=r2 src=r0 offset=0 imm=50
#line 240 "sample/undocked/map.c"
    r2 = IMMEDIATE(50);
label_79:
    // EBPF_OP_MOV64_IMM pc=1283 dst=r3 src=r0 offset=0 imm=-7
#line 240 "sample/undocked/map.c"
    r3 = IMMEDIATE(-7);
    // EBPF_OP_CALL pc=1284 dst=r0 src=r0 offset=0 imm=14
#line 240 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[7].address(r1, r2, r3, r4, r5, context);
#line 240 "sample/undocked/map.c"
    if ((runtime_context->helper_data[7].tail_call) && (r0 == 0)) {
#line 240 "sample/undocked/map.c"
        return 0;
#line 240 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1285 dst=r0 src=r0 offset=26 imm=0
#line 240 "sample/undocked/map.c"
    goto label_84;
label_80:
    // EBPF_OP_LDXW pc=1286 dst=r3 src=r10 offset=-4 imm=0
#line 240 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1287 dst=r3 src=r0 offset=90 imm=0
#line 240 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(0)) {
#line 240 "sample/undocked/map.c"
        goto label_89;
#line 240 "sample/undocked/map.c"
    }
label_81:
    // EBPF_OP_LDDW pc=1288 dst=r1 src=r0 offset=0 imm=1852404835
#line 240 "sample/undocked/map.c"
    r1 = (uint64_t)7216209606537213027;
    // EBPF_OP_STXDW pc=1290 dst=r10 src=r1 offset=-80 imm=0
#line 240 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1291 dst=r1 src=r0 offset=0 imm=543434016
#line 240 "sample/undocked/map.c"
    r1 = (uint64_t)7309474570952779040;
    // EBPF_OP_STXDW pc=1293 dst=r10 src=r1 offset=-88 imm=0
#line 240 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1294 dst=r1 src=r0 offset=0 imm=1701978221
#line 240 "sample/undocked/map.c"
    r1 = (uint64_t)7958552634295722093;
    // EBPF_OP_STXDW pc=1296 dst=r10 src=r1 offset=-96 imm=0
#line 240 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1297 dst=r1 src=r0 offset=0 imm=1801807216
#line 240 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=1299 dst=r10 src=r1 offset=-104 imm=0
#line 240 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1300 dst=r1 src=r0 offset=0 imm=1600548962
#line 240 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1302 dst=r10 src=r1 offset=-112 imm=0
#line 240 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_IMM pc=1303 dst=r1 src=r0 offset=0 imm=0
#line 240 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=1304 dst=r10 src=r1 offset=-72 imm=0
#line 240 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint8_t)r1;
    // EBPF_OP_MOV64_REG pc=1305 dst=r1 src=r10 offset=0 imm=0
#line 240 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1306 dst=r1 src=r0 offset=0 imm=-112
#line 240 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=1307 dst=r2 src=r0 offset=0 imm=41
#line 240 "sample/undocked/map.c"
    r2 = IMMEDIATE(41);
label_82:
    // EBPF_OP_MOV64_IMM pc=1308 dst=r4 src=r0 offset=0 imm=0
#line 240 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
label_83:
    // EBPF_OP_CALL pc=1309 dst=r0 src=r0 offset=0 imm=14
#line 240 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[7].address(r1, r2, r3, r4, r5, context);
#line 240 "sample/undocked/map.c"
    if ((runtime_context->helper_data[7].tail_call) && (r0 == 0)) {
#line 240 "sample/undocked/map.c"
        return 0;
#line 240 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=1310 dst=r6 src=r0 offset=0 imm=-1
#line 240 "sample/undocked/map.c"
    r6 = (uint64_t)4294967295;
label_84:
    // EBPF_OP_MOV64_REG pc=1312 dst=r3 src=r6 offset=0 imm=0
#line 303 "sample/undocked/map.c"
    r3 = r6;
    // EBPF_OP_LSH64_IMM pc=1313 dst=r3 src=r0 offset=0 imm=32
#line 303 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=1314 dst=r3 src=r0 offset=0 imm=32
#line 303 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=1315 dst=r3 src=r0 offset=1 imm=-1
#line 303 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 303 "sample/undocked/map.c"
        goto label_85;
#line 303 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1316 dst=r0 src=r0 offset=42 imm=0
#line 303 "sample/undocked/map.c"
    goto label_88;
label_85:
    // EBPF_OP_MOV64_IMM pc=1317 dst=r1 src=r0 offset=0 imm=0
#line 303 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1318 dst=r10 src=r1 offset=-4 imm=0
#line 240 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1319 dst=r2 src=r10 offset=0 imm=0
#line 240 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1320 dst=r2 src=r0 offset=0 imm=-4
#line 240 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1321 dst=r1 src=r1 offset=0 imm=8
#line 240 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_CALL pc=1323 dst=r0 src=r0 offset=0 imm=18
#line 240 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[6].address(r1, r2, r3, r4, r5, context);
#line 240 "sample/undocked/map.c"
    if ((runtime_context->helper_data[6].tail_call) && (r0 == 0)) {
#line 240 "sample/undocked/map.c"
        return 0;
#line 240 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1324 dst=r7 src=r0 offset=0 imm=0
#line 240 "sample/undocked/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=1325 dst=r4 src=r7 offset=0 imm=0
#line 240 "sample/undocked/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=1326 dst=r4 src=r0 offset=0 imm=32
#line 240 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1327 dst=r1 src=r4 offset=0 imm=0
#line 240 "sample/undocked/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=1328 dst=r1 src=r0 offset=0 imm=32
#line 240 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_LDDW pc=1329 dst=r2 src=r0 offset=0 imm=-7
#line 240 "sample/undocked/map.c"
    r2 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=1331 dst=r1 src=r2 offset=844 imm=0
#line 240 "sample/undocked/map.c"
    if (r1 == r2) {
#line 240 "sample/undocked/map.c"
        goto label_136;
#line 240 "sample/undocked/map.c"
    }
label_86:
    // EBPF_OP_MOV64_IMM pc=1332 dst=r1 src=r0 offset=0 imm=100
#line 240 "sample/undocked/map.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXH pc=1333 dst=r10 src=r1 offset=-64 imm=0
#line 240 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=1334 dst=r1 src=r0 offset=0 imm=1852994932
#line 240 "sample/undocked/map.c"
    r1 = (uint64_t)2675248565465544052;
    // EBPF_OP_STXDW pc=1336 dst=r10 src=r1 offset=-72 imm=0
#line 240 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1337 dst=r1 src=r0 offset=0 imm=622883948
#line 240 "sample/undocked/map.c"
    r1 = (uint64_t)7309940759667438700;
    // EBPF_OP_STXDW pc=1339 dst=r10 src=r1 offset=-80 imm=0
#line 240 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1340 dst=r1 src=r0 offset=0 imm=543649385
#line 240 "sample/undocked/map.c"
    r1 = (uint64_t)8463219665603620457;
    // EBPF_OP_STXDW pc=1342 dst=r10 src=r1 offset=-88 imm=0
#line 240 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1343 dst=r1 src=r0 offset=0 imm=2019893357
#line 240 "sample/undocked/map.c"
    r1 = (uint64_t)8386658464824631405;
    // EBPF_OP_STXDW pc=1345 dst=r10 src=r1 offset=-96 imm=0
#line 240 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1346 dst=r1 src=r0 offset=0 imm=1801807216
#line 240 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=1348 dst=r10 src=r1 offset=-104 imm=0
#line 240 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1349 dst=r1 src=r0 offset=0 imm=1600548962
#line 240 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1351 dst=r10 src=r1 offset=-112 imm=0
#line 240 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_ARSH64_IMM pc=1352 dst=r4 src=r0 offset=0 imm=32
#line 240 "sample/undocked/map.c"
    r4 = (int64_t)r4 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1353 dst=r1 src=r10 offset=0 imm=0
#line 240 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1354 dst=r1 src=r0 offset=0 imm=-112
#line 240 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=1355 dst=r2 src=r0 offset=0 imm=50
#line 240 "sample/undocked/map.c"
    r2 = IMMEDIATE(50);
label_87:
    // EBPF_OP_MOV64_IMM pc=1356 dst=r3 src=r0 offset=0 imm=-7
#line 240 "sample/undocked/map.c"
    r3 = IMMEDIATE(-7);
    // EBPF_OP_CALL pc=1357 dst=r0 src=r0 offset=0 imm=14
#line 240 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[7].address(r1, r2, r3, r4, r5, context);
#line 240 "sample/undocked/map.c"
    if ((runtime_context->helper_data[7].tail_call) && (r0 == 0)) {
#line 240 "sample/undocked/map.c"
        return 0;
#line 240 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1358 dst=r0 src=r0 offset=843 imm=0
#line 240 "sample/undocked/map.c"
    goto label_140;
label_88:
    // EBPF_OP_LDDW pc=1359 dst=r1 src=r0 offset=0 imm=1684369010
#line 240 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=1361 dst=r10 src=r1 offset=-80 imm=0
#line 303 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1362 dst=r1 src=r0 offset=0 imm=541414725
#line 303 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140578096453;
    // EBPF_OP_STXDW pc=1364 dst=r10 src=r1 offset=-88 imm=0
#line 303 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1365 dst=r1 src=r0 offset=0 imm=1634541682
#line 303 "sample/undocked/map.c"
    r1 = (uint64_t)6147730633380405362;
    // EBPF_OP_STXDW pc=1367 dst=r10 src=r1 offset=-96 imm=0
#line 303 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1368 dst=r1 src=r0 offset=0 imm=1330667336
#line 303 "sample/undocked/map.c"
    r1 = (uint64_t)8027138915134627656;
    // EBPF_OP_STXDW pc=1370 dst=r10 src=r1 offset=-104 imm=0
#line 303 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1371 dst=r1 src=r0 offset=0 imm=1953719636
#line 303 "sample/undocked/map.c"
    r1 = (uint64_t)6004793778491319636;
    // EBPF_OP_STXDW pc=1373 dst=r10 src=r1 offset=-112 imm=0
#line 303 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1374 dst=r1 src=r10 offset=0 imm=0
#line 303 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1375 dst=r1 src=r0 offset=0 imm=-112
#line 303 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=1376 dst=r2 src=r0 offset=0 imm=40
#line 303 "sample/undocked/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_JA pc=1377 dst=r0 src=r0 offset=-1277 imm=0
#line 303 "sample/undocked/map.c"
    goto label_8;
label_89:
    // EBPF_OP_STXW pc=1378 dst=r10 src=r7 offset=-4 imm=0
#line 241 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=1379 dst=r2 src=r10 offset=0 imm=0
#line 241 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1380 dst=r2 src=r0 offset=0 imm=-4
#line 241 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1381 dst=r1 src=r1 offset=0 imm=7
#line 241 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
    // EBPF_OP_CALL pc=1383 dst=r0 src=r0 offset=0 imm=17
#line 241 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[8].address(r1, r2, r3, r4, r5, context);
#line 241 "sample/undocked/map.c"
    if ((runtime_context->helper_data[8].tail_call) && (r0 == 0)) {
#line 241 "sample/undocked/map.c"
        return 0;
#line 241 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1384 dst=r6 src=r0 offset=0 imm=0
#line 241 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1385 dst=r4 src=r6 offset=0 imm=0
#line 241 "sample/undocked/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=1386 dst=r4 src=r0 offset=0 imm=32
#line 241 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1387 dst=r1 src=r4 offset=0 imm=0
#line 241 "sample/undocked/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=1388 dst=r1 src=r0 offset=0 imm=32
#line 241 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_LDDW pc=1389 dst=r2 src=r0 offset=0 imm=-7
#line 241 "sample/undocked/map.c"
    r2 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=1391 dst=r1 src=r2 offset=24 imm=0
#line 241 "sample/undocked/map.c"
    if (r1 == r2) {
#line 241 "sample/undocked/map.c"
        goto label_91;
#line 241 "sample/undocked/map.c"
    }
label_90:
    // EBPF_OP_STXB pc=1392 dst=r10 src=r7 offset=-64 imm=0
#line 241 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint8_t)r7;
    // EBPF_OP_LDDW pc=1393 dst=r1 src=r0 offset=0 imm=1701737077
#line 241 "sample/undocked/map.c"
    r1 = (uint64_t)7216209593501643381;
    // EBPF_OP_STXDW pc=1395 dst=r10 src=r1 offset=-72 imm=0
#line 241 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1396 dst=r1 src=r0 offset=0 imm=1680154740
#line 241 "sample/undocked/map.c"
    r1 = (uint64_t)8387235364492091508;
    // EBPF_OP_STXDW pc=1398 dst=r10 src=r1 offset=-80 imm=0
#line 241 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1399 dst=r1 src=r0 offset=0 imm=1914726254
#line 241 "sample/undocked/map.c"
    r1 = (uint64_t)7815279607914981230;
    // EBPF_OP_STXDW pc=1401 dst=r10 src=r1 offset=-88 imm=0
#line 241 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1402 dst=r1 src=r0 offset=0 imm=1886938400
#line 241 "sample/undocked/map.c"
    r1 = (uint64_t)7598807758610654496;
    // EBPF_OP_STXDW pc=1404 dst=r10 src=r1 offset=-96 imm=0
#line 241 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1405 dst=r1 src=r0 offset=0 imm=1601204080
#line 241 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=1407 dst=r10 src=r1 offset=-104 imm=0
#line 241 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1408 dst=r1 src=r0 offset=0 imm=1600548962
#line 241 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1410 dst=r10 src=r1 offset=-112 imm=0
#line 241 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_ARSH64_IMM pc=1411 dst=r4 src=r0 offset=0 imm=32
#line 241 "sample/undocked/map.c"
    r4 = (int64_t)r4 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1412 dst=r1 src=r10 offset=0 imm=0
#line 241 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1413 dst=r1 src=r0 offset=0 imm=-112
#line 241 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=1414 dst=r2 src=r0 offset=0 imm=49
#line 241 "sample/undocked/map.c"
    r2 = IMMEDIATE(49);
    // EBPF_OP_JA pc=1415 dst=r0 src=r0 offset=-133 imm=0
#line 241 "sample/undocked/map.c"
    goto label_79;
label_91:
    // EBPF_OP_LDXW pc=1416 dst=r3 src=r10 offset=-4 imm=0
#line 241 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1417 dst=r3 src=r0 offset=19 imm=0
#line 241 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(0)) {
#line 241 "sample/undocked/map.c"
        goto label_93;
#line 241 "sample/undocked/map.c"
    }
label_92:
    // EBPF_OP_LDDW pc=1418 dst=r1 src=r0 offset=0 imm=1735289204
#line 241 "sample/undocked/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=1420 dst=r10 src=r1 offset=-80 imm=0
#line 241 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1421 dst=r1 src=r0 offset=0 imm=1696621605
#line 241 "sample/undocked/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=1423 dst=r10 src=r1 offset=-88 imm=0
#line 241 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1424 dst=r1 src=r0 offset=0 imm=1952805408
#line 241 "sample/undocked/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=1426 dst=r10 src=r1 offset=-96 imm=0
#line 241 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1427 dst=r1 src=r0 offset=0 imm=1601204080
#line 241 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=1429 dst=r10 src=r1 offset=-104 imm=0
#line 241 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1430 dst=r1 src=r0 offset=0 imm=1600548962
#line 241 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1432 dst=r10 src=r1 offset=-112 imm=0
#line 241 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1433 dst=r1 src=r10 offset=0 imm=0
#line 241 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1434 dst=r1 src=r0 offset=0 imm=-112
#line 241 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=1435 dst=r2 src=r0 offset=0 imm=40
#line 241 "sample/undocked/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_JA pc=1436 dst=r0 src=r0 offset=-129 imm=0
#line 241 "sample/undocked/map.c"
    goto label_82;
label_93:
    // EBPF_OP_STXW pc=1437 dst=r10 src=r7 offset=-4 imm=0
#line 249 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=1438 dst=r2 src=r10 offset=0 imm=0
#line 249 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1439 dst=r2 src=r0 offset=0 imm=-4
#line 249 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1440 dst=r1 src=r1 offset=0 imm=7
#line 249 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
    // EBPF_OP_MOV64_IMM pc=1442 dst=r3 src=r0 offset=0 imm=0
#line 249 "sample/undocked/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1443 dst=r0 src=r0 offset=0 imm=16
#line 249 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[9].address(r1, r2, r3, r4, r5, context);
#line 249 "sample/undocked/map.c"
    if ((runtime_context->helper_data[9].tail_call) && (r0 == 0)) {
#line 249 "sample/undocked/map.c"
        return 0;
#line 249 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1444 dst=r6 src=r0 offset=0 imm=0
#line 249 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1445 dst=r5 src=r6 offset=0 imm=0
#line 249 "sample/undocked/map.c"
    r5 = r6;
    // EBPF_OP_LSH64_IMM pc=1446 dst=r5 src=r0 offset=0 imm=32
#line 249 "sample/undocked/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1447 dst=r1 src=r5 offset=0 imm=0
#line 249 "sample/undocked/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=1448 dst=r1 src=r0 offset=0 imm=32
#line 249 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=1449 dst=r1 src=r0 offset=31 imm=0
#line 249 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 249 "sample/undocked/map.c"
        goto label_97;
#line 249 "sample/undocked/map.c"
    }
label_94:
    // EBPF_OP_MOV64_IMM pc=1450 dst=r1 src=r0 offset=0 imm=25637
#line 249 "sample/undocked/map.c"
    r1 = IMMEDIATE(25637);
    // EBPF_OP_STXH pc=1451 dst=r10 src=r1 offset=-60 imm=0
#line 249 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-60)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=1452 dst=r1 src=r0 offset=0 imm=543450478
#line 249 "sample/undocked/map.c"
    r1 = IMMEDIATE(543450478);
    // EBPF_OP_STXW pc=1453 dst=r10 src=r1 offset=-64 imm=0
#line 249 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=1454 dst=r1 src=r0 offset=0 imm=1914725413
#line 249 "sample/undocked/map.c"
    r1 = (uint64_t)8247626271654175781;
    // EBPF_OP_STXDW pc=1456 dst=r10 src=r1 offset=-72 imm=0
#line 249 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1457 dst=r1 src=r0 offset=0 imm=1667592312
#line 249 "sample/undocked/map.c"
    r1 = (uint64_t)2334102057442963576;
    // EBPF_OP_STXDW pc=1459 dst=r10 src=r1 offset=-80 imm=0
#line 249 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1460 dst=r1 src=r0 offset=0 imm=543649385
#line 249 "sample/undocked/map.c"
    r1 = (uint64_t)7286934307705679465;
    // EBPF_OP_STXDW pc=1462 dst=r10 src=r1 offset=-88 imm=0
#line 249 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1463 dst=r1 src=r0 offset=0 imm=1852383341
#line 249 "sample/undocked/map.c"
    r1 = (uint64_t)8390880602192683117;
    // EBPF_OP_STXDW pc=1465 dst=r10 src=r1 offset=-96 imm=0
#line 249 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1466 dst=r1 src=r0 offset=0 imm=1752397168
#line 249 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755764168048;
    // EBPF_OP_STXDW pc=1468 dst=r10 src=r1 offset=-104 imm=0
#line 249 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1469 dst=r1 src=r0 offset=0 imm=1600548962
#line 249 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1471 dst=r10 src=r1 offset=-112 imm=0
#line 249 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_STXB pc=1472 dst=r10 src=r7 offset=-58 imm=0
#line 249 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-58)) = (uint8_t)r7;
label_95:
    // EBPF_OP_LDXW pc=1473 dst=r3 src=r10 offset=-4 imm=0
#line 249 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_ARSH64_IMM pc=1474 dst=r5 src=r0 offset=0 imm=32
#line 249 "sample/undocked/map.c"
    r5 = (int64_t)r5 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1475 dst=r1 src=r10 offset=0 imm=0
#line 249 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1476 dst=r1 src=r0 offset=0 imm=-112
#line 249 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=1477 dst=r2 src=r0 offset=0 imm=55
#line 249 "sample/undocked/map.c"
    r2 = IMMEDIATE(55);
    // EBPF_OP_MOV64_IMM pc=1478 dst=r4 src=r0 offset=0 imm=0
#line 249 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
label_96:
    // EBPF_OP_CALL pc=1479 dst=r0 src=r0 offset=0 imm=15
#line 249 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[10].address(r1, r2, r3, r4, r5, context);
#line 249 "sample/undocked/map.c"
    if ((runtime_context->helper_data[10].tail_call) && (r0 == 0)) {
#line 249 "sample/undocked/map.c"
        return 0;
#line 249 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1480 dst=r0 src=r0 offset=-169 imm=0
#line 249 "sample/undocked/map.c"
    goto label_84;
label_97:
    // EBPF_OP_MOV64_IMM pc=1481 dst=r1 src=r0 offset=0 imm=1
#line 249 "sample/undocked/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=1482 dst=r10 src=r1 offset=-4 imm=0
#line 250 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1483 dst=r2 src=r10 offset=0 imm=0
#line 250 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1484 dst=r2 src=r0 offset=0 imm=-4
#line 250 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1485 dst=r1 src=r1 offset=0 imm=7
#line 250 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
    // EBPF_OP_MOV64_IMM pc=1487 dst=r3 src=r0 offset=0 imm=0
#line 250 "sample/undocked/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1488 dst=r0 src=r0 offset=0 imm=16
#line 250 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[9].address(r1, r2, r3, r4, r5, context);
#line 250 "sample/undocked/map.c"
    if ((runtime_context->helper_data[9].tail_call) && (r0 == 0)) {
#line 250 "sample/undocked/map.c"
        return 0;
#line 250 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1489 dst=r6 src=r0 offset=0 imm=0
#line 250 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1490 dst=r5 src=r6 offset=0 imm=0
#line 250 "sample/undocked/map.c"
    r5 = r6;
    // EBPF_OP_LSH64_IMM pc=1491 dst=r5 src=r0 offset=0 imm=32
#line 250 "sample/undocked/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1492 dst=r1 src=r5 offset=0 imm=0
#line 250 "sample/undocked/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=1493 dst=r1 src=r0 offset=0 imm=32
#line 250 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=1494 dst=r1 src=r0 offset=1 imm=0
#line 250 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 250 "sample/undocked/map.c"
        goto label_98;
#line 250 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1495 dst=r0 src=r0 offset=-46 imm=0
#line 250 "sample/undocked/map.c"
    goto label_94;
label_98:
    // EBPF_OP_MOV64_IMM pc=1496 dst=r1 src=r0 offset=0 imm=2
#line 250 "sample/undocked/map.c"
    r1 = IMMEDIATE(2);
    // EBPF_OP_STXW pc=1497 dst=r10 src=r1 offset=-4 imm=0
#line 251 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1498 dst=r2 src=r10 offset=0 imm=0
#line 251 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1499 dst=r2 src=r0 offset=0 imm=-4
#line 251 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1500 dst=r1 src=r1 offset=0 imm=7
#line 251 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
    // EBPF_OP_MOV64_IMM pc=1502 dst=r3 src=r0 offset=0 imm=0
#line 251 "sample/undocked/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1503 dst=r0 src=r0 offset=0 imm=16
#line 251 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[9].address(r1, r2, r3, r4, r5, context);
#line 251 "sample/undocked/map.c"
    if ((runtime_context->helper_data[9].tail_call) && (r0 == 0)) {
#line 251 "sample/undocked/map.c"
        return 0;
#line 251 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1504 dst=r6 src=r0 offset=0 imm=0
#line 251 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1505 dst=r5 src=r6 offset=0 imm=0
#line 251 "sample/undocked/map.c"
    r5 = r6;
    // EBPF_OP_LSH64_IMM pc=1506 dst=r5 src=r0 offset=0 imm=32
#line 251 "sample/undocked/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1507 dst=r1 src=r5 offset=0 imm=0
#line 251 "sample/undocked/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=1508 dst=r1 src=r0 offset=0 imm=32
#line 251 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=1509 dst=r1 src=r0 offset=1 imm=0
#line 251 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 251 "sample/undocked/map.c"
        goto label_99;
#line 251 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1510 dst=r0 src=r0 offset=-61 imm=0
#line 251 "sample/undocked/map.c"
    goto label_94;
label_99:
    // EBPF_OP_MOV64_IMM pc=1511 dst=r1 src=r0 offset=0 imm=3
#line 251 "sample/undocked/map.c"
    r1 = IMMEDIATE(3);
    // EBPF_OP_STXW pc=1512 dst=r10 src=r1 offset=-4 imm=0
#line 252 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1513 dst=r2 src=r10 offset=0 imm=0
#line 252 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1514 dst=r2 src=r0 offset=0 imm=-4
#line 252 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1515 dst=r1 src=r1 offset=0 imm=7
#line 252 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
    // EBPF_OP_MOV64_IMM pc=1517 dst=r3 src=r0 offset=0 imm=0
#line 252 "sample/undocked/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1518 dst=r0 src=r0 offset=0 imm=16
#line 252 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[9].address(r1, r2, r3, r4, r5, context);
#line 252 "sample/undocked/map.c"
    if ((runtime_context->helper_data[9].tail_call) && (r0 == 0)) {
#line 252 "sample/undocked/map.c"
        return 0;
#line 252 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1519 dst=r6 src=r0 offset=0 imm=0
#line 252 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1520 dst=r5 src=r6 offset=0 imm=0
#line 252 "sample/undocked/map.c"
    r5 = r6;
    // EBPF_OP_LSH64_IMM pc=1521 dst=r5 src=r0 offset=0 imm=32
#line 252 "sample/undocked/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1522 dst=r1 src=r5 offset=0 imm=0
#line 252 "sample/undocked/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=1523 dst=r1 src=r0 offset=0 imm=32
#line 252 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=1524 dst=r1 src=r0 offset=1 imm=0
#line 252 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 252 "sample/undocked/map.c"
        goto label_100;
#line 252 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1525 dst=r0 src=r0 offset=-76 imm=0
#line 252 "sample/undocked/map.c"
    goto label_94;
label_100:
    // EBPF_OP_MOV64_IMM pc=1526 dst=r1 src=r0 offset=0 imm=4
#line 252 "sample/undocked/map.c"
    r1 = IMMEDIATE(4);
    // EBPF_OP_STXW pc=1527 dst=r10 src=r1 offset=-4 imm=0
#line 253 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1528 dst=r2 src=r10 offset=0 imm=0
#line 253 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1529 dst=r2 src=r0 offset=0 imm=-4
#line 253 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1530 dst=r1 src=r1 offset=0 imm=7
#line 253 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
    // EBPF_OP_MOV64_IMM pc=1532 dst=r3 src=r0 offset=0 imm=0
#line 253 "sample/undocked/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1533 dst=r0 src=r0 offset=0 imm=16
#line 253 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[9].address(r1, r2, r3, r4, r5, context);
#line 253 "sample/undocked/map.c"
    if ((runtime_context->helper_data[9].tail_call) && (r0 == 0)) {
#line 253 "sample/undocked/map.c"
        return 0;
#line 253 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1534 dst=r6 src=r0 offset=0 imm=0
#line 253 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1535 dst=r5 src=r6 offset=0 imm=0
#line 253 "sample/undocked/map.c"
    r5 = r6;
    // EBPF_OP_LSH64_IMM pc=1536 dst=r5 src=r0 offset=0 imm=32
#line 253 "sample/undocked/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1537 dst=r1 src=r5 offset=0 imm=0
#line 253 "sample/undocked/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=1538 dst=r1 src=r0 offset=0 imm=32
#line 253 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=1539 dst=r1 src=r0 offset=1 imm=0
#line 253 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 253 "sample/undocked/map.c"
        goto label_101;
#line 253 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1540 dst=r0 src=r0 offset=-91 imm=0
#line 253 "sample/undocked/map.c"
    goto label_94;
label_101:
    // EBPF_OP_MOV64_IMM pc=1541 dst=r1 src=r0 offset=0 imm=5
#line 253 "sample/undocked/map.c"
    r1 = IMMEDIATE(5);
    // EBPF_OP_STXW pc=1542 dst=r10 src=r1 offset=-4 imm=0
#line 254 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1543 dst=r2 src=r10 offset=0 imm=0
#line 254 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1544 dst=r2 src=r0 offset=0 imm=-4
#line 254 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1545 dst=r1 src=r1 offset=0 imm=7
#line 254 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
    // EBPF_OP_MOV64_IMM pc=1547 dst=r3 src=r0 offset=0 imm=0
#line 254 "sample/undocked/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1548 dst=r0 src=r0 offset=0 imm=16
#line 254 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[9].address(r1, r2, r3, r4, r5, context);
#line 254 "sample/undocked/map.c"
    if ((runtime_context->helper_data[9].tail_call) && (r0 == 0)) {
#line 254 "sample/undocked/map.c"
        return 0;
#line 254 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1549 dst=r6 src=r0 offset=0 imm=0
#line 254 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1550 dst=r5 src=r6 offset=0 imm=0
#line 254 "sample/undocked/map.c"
    r5 = r6;
    // EBPF_OP_LSH64_IMM pc=1551 dst=r5 src=r0 offset=0 imm=32
#line 254 "sample/undocked/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1552 dst=r1 src=r5 offset=0 imm=0
#line 254 "sample/undocked/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=1553 dst=r1 src=r0 offset=0 imm=32
#line 254 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=1554 dst=r1 src=r0 offset=1 imm=0
#line 254 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 254 "sample/undocked/map.c"
        goto label_102;
#line 254 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1555 dst=r0 src=r0 offset=-106 imm=0
#line 254 "sample/undocked/map.c"
    goto label_94;
label_102:
    // EBPF_OP_MOV64_IMM pc=1556 dst=r1 src=r0 offset=0 imm=6
#line 254 "sample/undocked/map.c"
    r1 = IMMEDIATE(6);
    // EBPF_OP_STXW pc=1557 dst=r10 src=r1 offset=-4 imm=0
#line 255 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1558 dst=r2 src=r10 offset=0 imm=0
#line 255 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1559 dst=r2 src=r0 offset=0 imm=-4
#line 255 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1560 dst=r1 src=r1 offset=0 imm=7
#line 255 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
    // EBPF_OP_MOV64_IMM pc=1562 dst=r3 src=r0 offset=0 imm=0
#line 255 "sample/undocked/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1563 dst=r0 src=r0 offset=0 imm=16
#line 255 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[9].address(r1, r2, r3, r4, r5, context);
#line 255 "sample/undocked/map.c"
    if ((runtime_context->helper_data[9].tail_call) && (r0 == 0)) {
#line 255 "sample/undocked/map.c"
        return 0;
#line 255 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1564 dst=r6 src=r0 offset=0 imm=0
#line 255 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1565 dst=r5 src=r6 offset=0 imm=0
#line 255 "sample/undocked/map.c"
    r5 = r6;
    // EBPF_OP_LSH64_IMM pc=1566 dst=r5 src=r0 offset=0 imm=32
#line 255 "sample/undocked/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1567 dst=r1 src=r5 offset=0 imm=0
#line 255 "sample/undocked/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=1568 dst=r1 src=r0 offset=0 imm=32
#line 255 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=1569 dst=r1 src=r0 offset=1 imm=0
#line 255 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 255 "sample/undocked/map.c"
        goto label_103;
#line 255 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1570 dst=r0 src=r0 offset=-121 imm=0
#line 255 "sample/undocked/map.c"
    goto label_94;
label_103:
    // EBPF_OP_MOV64_IMM pc=1571 dst=r1 src=r0 offset=0 imm=7
#line 255 "sample/undocked/map.c"
    r1 = IMMEDIATE(7);
    // EBPF_OP_STXW pc=1572 dst=r10 src=r1 offset=-4 imm=0
#line 256 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1573 dst=r2 src=r10 offset=0 imm=0
#line 256 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1574 dst=r2 src=r0 offset=0 imm=-4
#line 256 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1575 dst=r1 src=r1 offset=0 imm=7
#line 256 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
    // EBPF_OP_MOV64_IMM pc=1577 dst=r3 src=r0 offset=0 imm=0
#line 256 "sample/undocked/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1578 dst=r0 src=r0 offset=0 imm=16
#line 256 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[9].address(r1, r2, r3, r4, r5, context);
#line 256 "sample/undocked/map.c"
    if ((runtime_context->helper_data[9].tail_call) && (r0 == 0)) {
#line 256 "sample/undocked/map.c"
        return 0;
#line 256 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1579 dst=r6 src=r0 offset=0 imm=0
#line 256 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1580 dst=r5 src=r6 offset=0 imm=0
#line 256 "sample/undocked/map.c"
    r5 = r6;
    // EBPF_OP_LSH64_IMM pc=1581 dst=r5 src=r0 offset=0 imm=32
#line 256 "sample/undocked/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1582 dst=r1 src=r5 offset=0 imm=0
#line 256 "sample/undocked/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=1583 dst=r1 src=r0 offset=0 imm=32
#line 256 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=1584 dst=r1 src=r0 offset=1 imm=0
#line 256 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 256 "sample/undocked/map.c"
        goto label_104;
#line 256 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1585 dst=r0 src=r0 offset=-136 imm=0
#line 256 "sample/undocked/map.c"
    goto label_94;
label_104:
    // EBPF_OP_MOV64_IMM pc=1586 dst=r1 src=r0 offset=0 imm=8
#line 256 "sample/undocked/map.c"
    r1 = IMMEDIATE(8);
    // EBPF_OP_STXW pc=1587 dst=r10 src=r1 offset=-4 imm=0
#line 257 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1588 dst=r2 src=r10 offset=0 imm=0
#line 257 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1589 dst=r2 src=r0 offset=0 imm=-4
#line 257 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1590 dst=r1 src=r1 offset=0 imm=7
#line 257 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
    // EBPF_OP_MOV64_IMM pc=1592 dst=r3 src=r0 offset=0 imm=0
#line 257 "sample/undocked/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1593 dst=r0 src=r0 offset=0 imm=16
#line 257 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[9].address(r1, r2, r3, r4, r5, context);
#line 257 "sample/undocked/map.c"
    if ((runtime_context->helper_data[9].tail_call) && (r0 == 0)) {
#line 257 "sample/undocked/map.c"
        return 0;
#line 257 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1594 dst=r6 src=r0 offset=0 imm=0
#line 257 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1595 dst=r5 src=r6 offset=0 imm=0
#line 257 "sample/undocked/map.c"
    r5 = r6;
    // EBPF_OP_LSH64_IMM pc=1596 dst=r5 src=r0 offset=0 imm=32
#line 257 "sample/undocked/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1597 dst=r1 src=r5 offset=0 imm=0
#line 257 "sample/undocked/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=1598 dst=r1 src=r0 offset=0 imm=32
#line 257 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=1599 dst=r1 src=r0 offset=1 imm=0
#line 257 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 257 "sample/undocked/map.c"
        goto label_105;
#line 257 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1600 dst=r0 src=r0 offset=-151 imm=0
#line 257 "sample/undocked/map.c"
    goto label_94;
label_105:
    // EBPF_OP_MOV64_IMM pc=1601 dst=r1 src=r0 offset=0 imm=9
#line 257 "sample/undocked/map.c"
    r1 = IMMEDIATE(9);
    // EBPF_OP_STXW pc=1602 dst=r10 src=r1 offset=-4 imm=0
#line 258 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1603 dst=r2 src=r10 offset=0 imm=0
#line 258 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1604 dst=r2 src=r0 offset=0 imm=-4
#line 258 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1605 dst=r1 src=r1 offset=0 imm=7
#line 258 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
    // EBPF_OP_MOV64_IMM pc=1607 dst=r3 src=r0 offset=0 imm=0
#line 258 "sample/undocked/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1608 dst=r0 src=r0 offset=0 imm=16
#line 258 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[9].address(r1, r2, r3, r4, r5, context);
#line 258 "sample/undocked/map.c"
    if ((runtime_context->helper_data[9].tail_call) && (r0 == 0)) {
#line 258 "sample/undocked/map.c"
        return 0;
#line 258 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1609 dst=r6 src=r0 offset=0 imm=0
#line 258 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1610 dst=r5 src=r6 offset=0 imm=0
#line 258 "sample/undocked/map.c"
    r5 = r6;
    // EBPF_OP_LSH64_IMM pc=1611 dst=r5 src=r0 offset=0 imm=32
#line 258 "sample/undocked/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1612 dst=r1 src=r5 offset=0 imm=0
#line 258 "sample/undocked/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=1613 dst=r1 src=r0 offset=0 imm=32
#line 258 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=1614 dst=r1 src=r0 offset=1 imm=0
#line 258 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 258 "sample/undocked/map.c"
        goto label_106;
#line 258 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1615 dst=r0 src=r0 offset=-166 imm=0
#line 258 "sample/undocked/map.c"
    goto label_94;
label_106:
    // EBPF_OP_MOV64_IMM pc=1616 dst=r7 src=r0 offset=0 imm=10
#line 258 "sample/undocked/map.c"
    r7 = IMMEDIATE(10);
    // EBPF_OP_STXW pc=1617 dst=r10 src=r7 offset=-4 imm=0
#line 261 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=1618 dst=r2 src=r10 offset=0 imm=0
#line 261 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1619 dst=r2 src=r0 offset=0 imm=-4
#line 261 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_IMM pc=1620 dst=r8 src=r0 offset=0 imm=0
#line 261 "sample/undocked/map.c"
    r8 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=1621 dst=r1 src=r1 offset=0 imm=7
#line 261 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
    // EBPF_OP_MOV64_IMM pc=1623 dst=r3 src=r0 offset=0 imm=0
#line 261 "sample/undocked/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1624 dst=r0 src=r0 offset=0 imm=16
#line 261 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[9].address(r1, r2, r3, r4, r5, context);
#line 261 "sample/undocked/map.c"
    if ((runtime_context->helper_data[9].tail_call) && (r0 == 0)) {
#line 261 "sample/undocked/map.c"
        return 0;
#line 261 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1625 dst=r6 src=r0 offset=0 imm=0
#line 261 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1626 dst=r5 src=r6 offset=0 imm=0
#line 261 "sample/undocked/map.c"
    r5 = r6;
    // EBPF_OP_LSH64_IMM pc=1627 dst=r5 src=r0 offset=0 imm=32
#line 261 "sample/undocked/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1628 dst=r1 src=r5 offset=0 imm=0
#line 261 "sample/undocked/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=1629 dst=r1 src=r0 offset=0 imm=32
#line 261 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_LDDW pc=1630 dst=r2 src=r0 offset=0 imm=-29
#line 261 "sample/undocked/map.c"
    r2 = (uint64_t)4294967267;
    // EBPF_OP_JEQ_REG pc=1632 dst=r1 src=r2 offset=30 imm=0
#line 261 "sample/undocked/map.c"
    if (r1 == r2) {
#line 261 "sample/undocked/map.c"
        goto label_107;
#line 261 "sample/undocked/map.c"
    }
    // EBPF_OP_STXB pc=1633 dst=r10 src=r8 offset=-58 imm=0
#line 261 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-58)) = (uint8_t)r8;
    // EBPF_OP_MOV64_IMM pc=1634 dst=r1 src=r0 offset=0 imm=25637
#line 261 "sample/undocked/map.c"
    r1 = IMMEDIATE(25637);
    // EBPF_OP_STXH pc=1635 dst=r10 src=r1 offset=-60 imm=0
#line 261 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-60)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=1636 dst=r1 src=r0 offset=0 imm=543450478
#line 261 "sample/undocked/map.c"
    r1 = IMMEDIATE(543450478);
    // EBPF_OP_STXW pc=1637 dst=r10 src=r1 offset=-64 imm=0
#line 261 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=1638 dst=r1 src=r0 offset=0 imm=1914725413
#line 261 "sample/undocked/map.c"
    r1 = (uint64_t)8247626271654175781;
    // EBPF_OP_STXDW pc=1640 dst=r10 src=r1 offset=-72 imm=0
#line 261 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1641 dst=r1 src=r0 offset=0 imm=1667592312
#line 261 "sample/undocked/map.c"
    r1 = (uint64_t)2334102057442963576;
    // EBPF_OP_STXDW pc=1643 dst=r10 src=r1 offset=-80 imm=0
#line 261 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1644 dst=r1 src=r0 offset=0 imm=543649385
#line 261 "sample/undocked/map.c"
    r1 = (uint64_t)7286934307705679465;
    // EBPF_OP_STXDW pc=1646 dst=r10 src=r1 offset=-88 imm=0
#line 261 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1647 dst=r1 src=r0 offset=0 imm=1852383341
#line 261 "sample/undocked/map.c"
    r1 = (uint64_t)8390880602192683117;
    // EBPF_OP_STXDW pc=1649 dst=r10 src=r1 offset=-96 imm=0
#line 261 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1650 dst=r1 src=r0 offset=0 imm=1752397168
#line 261 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755764168048;
    // EBPF_OP_STXDW pc=1652 dst=r10 src=r1 offset=-104 imm=0
#line 261 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1653 dst=r1 src=r0 offset=0 imm=1600548962
#line 261 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1655 dst=r10 src=r1 offset=-112 imm=0
#line 261 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=1656 dst=r3 src=r10 offset=-4 imm=0
#line 261 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_ARSH64_IMM pc=1657 dst=r5 src=r0 offset=0 imm=32
#line 261 "sample/undocked/map.c"
    r5 = (int64_t)r5 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1658 dst=r1 src=r10 offset=0 imm=0
#line 261 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1659 dst=r1 src=r0 offset=0 imm=-112
#line 261 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=1660 dst=r2 src=r0 offset=0 imm=55
#line 261 "sample/undocked/map.c"
    r2 = IMMEDIATE(55);
    // EBPF_OP_MOV64_IMM pc=1661 dst=r4 src=r0 offset=0 imm=-29
#line 261 "sample/undocked/map.c"
    r4 = IMMEDIATE(-29);
    // EBPF_OP_JA pc=1662 dst=r0 src=r0 offset=-184 imm=0
#line 261 "sample/undocked/map.c"
    goto label_96;
label_107:
    // EBPF_OP_STXW pc=1663 dst=r10 src=r7 offset=-4 imm=0
#line 262 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=1664 dst=r2 src=r10 offset=0 imm=0
#line 262 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1665 dst=r2 src=r0 offset=0 imm=-4
#line 262 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1666 dst=r1 src=r1 offset=0 imm=7
#line 262 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
    // EBPF_OP_MOV64_IMM pc=1668 dst=r3 src=r0 offset=0 imm=2
#line 262 "sample/undocked/map.c"
    r3 = IMMEDIATE(2);
    // EBPF_OP_CALL pc=1669 dst=r0 src=r0 offset=0 imm=16
#line 262 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[9].address(r1, r2, r3, r4, r5, context);
#line 262 "sample/undocked/map.c"
    if ((runtime_context->helper_data[9].tail_call) && (r0 == 0)) {
#line 262 "sample/undocked/map.c"
        return 0;
#line 262 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1670 dst=r6 src=r0 offset=0 imm=0
#line 262 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1671 dst=r5 src=r6 offset=0 imm=0
#line 262 "sample/undocked/map.c"
    r5 = r6;
    // EBPF_OP_LSH64_IMM pc=1672 dst=r5 src=r0 offset=0 imm=32
#line 262 "sample/undocked/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1673 dst=r1 src=r5 offset=0 imm=0
#line 262 "sample/undocked/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=1674 dst=r1 src=r0 offset=0 imm=32
#line 262 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=1675 dst=r1 src=r0 offset=25 imm=0
#line 262 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 262 "sample/undocked/map.c"
        goto label_108;
#line 262 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_IMM pc=1676 dst=r1 src=r0 offset=0 imm=25637
#line 262 "sample/undocked/map.c"
    r1 = IMMEDIATE(25637);
    // EBPF_OP_STXH pc=1677 dst=r10 src=r1 offset=-60 imm=0
#line 262 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-60)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=1678 dst=r1 src=r0 offset=0 imm=543450478
#line 262 "sample/undocked/map.c"
    r1 = IMMEDIATE(543450478);
    // EBPF_OP_STXW pc=1679 dst=r10 src=r1 offset=-64 imm=0
#line 262 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=1680 dst=r1 src=r0 offset=0 imm=1914725413
#line 262 "sample/undocked/map.c"
    r1 = (uint64_t)8247626271654175781;
    // EBPF_OP_STXDW pc=1682 dst=r10 src=r1 offset=-72 imm=0
#line 262 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1683 dst=r1 src=r0 offset=0 imm=1667592312
#line 262 "sample/undocked/map.c"
    r1 = (uint64_t)2334102057442963576;
    // EBPF_OP_STXDW pc=1685 dst=r10 src=r1 offset=-80 imm=0
#line 262 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1686 dst=r1 src=r0 offset=0 imm=543649385
#line 262 "sample/undocked/map.c"
    r1 = (uint64_t)7286934307705679465;
    // EBPF_OP_STXDW pc=1688 dst=r10 src=r1 offset=-88 imm=0
#line 262 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1689 dst=r1 src=r0 offset=0 imm=1852383341
#line 262 "sample/undocked/map.c"
    r1 = (uint64_t)8390880602192683117;
    // EBPF_OP_STXDW pc=1691 dst=r10 src=r1 offset=-96 imm=0
#line 262 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1692 dst=r1 src=r0 offset=0 imm=1752397168
#line 262 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755764168048;
    // EBPF_OP_STXDW pc=1694 dst=r10 src=r1 offset=-104 imm=0
#line 262 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1695 dst=r1 src=r0 offset=0 imm=1600548962
#line 262 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1697 dst=r10 src=r1 offset=-112 imm=0
#line 262 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_IMM pc=1698 dst=r1 src=r0 offset=0 imm=0
#line 262 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=1699 dst=r10 src=r1 offset=-58 imm=0
#line 262 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-58)) = (uint8_t)r1;
    // EBPF_OP_JA pc=1700 dst=r0 src=r0 offset=-228 imm=0
#line 262 "sample/undocked/map.c"
    goto label_95;
label_108:
    // EBPF_OP_MOV64_IMM pc=1701 dst=r1 src=r0 offset=0 imm=0
#line 262 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1702 dst=r10 src=r1 offset=-4 imm=0
#line 264 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=1703 dst=r2 src=r10 offset=0 imm=0
#line 264 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1704 dst=r2 src=r0 offset=0 imm=-4
#line 264 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1705 dst=r1 src=r1 offset=0 imm=7
#line 264 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
    // EBPF_OP_CALL pc=1707 dst=r0 src=r0 offset=0 imm=18
#line 264 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[6].address(r1, r2, r3, r4, r5, context);
#line 264 "sample/undocked/map.c"
    if ((runtime_context->helper_data[6].tail_call) && (r0 == 0)) {
#line 264 "sample/undocked/map.c"
        return 0;
#line 264 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1708 dst=r6 src=r0 offset=0 imm=0
#line 264 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1709 dst=r4 src=r6 offset=0 imm=0
#line 264 "sample/undocked/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=1710 dst=r4 src=r0 offset=0 imm=32
#line 264 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1711 dst=r1 src=r4 offset=0 imm=0
#line 264 "sample/undocked/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=1712 dst=r1 src=r0 offset=0 imm=32
#line 264 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=1713 dst=r1 src=r0 offset=25 imm=0
#line 264 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 264 "sample/undocked/map.c"
        goto label_109;
#line 264 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_IMM pc=1714 dst=r1 src=r0 offset=0 imm=100
#line 264 "sample/undocked/map.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXH pc=1715 dst=r10 src=r1 offset=-64 imm=0
#line 264 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=1716 dst=r1 src=r0 offset=0 imm=1852994932
#line 264 "sample/undocked/map.c"
    r1 = (uint64_t)2675248565465544052;
    // EBPF_OP_STXDW pc=1718 dst=r10 src=r1 offset=-72 imm=0
#line 264 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1719 dst=r1 src=r0 offset=0 imm=622883948
#line 264 "sample/undocked/map.c"
    r1 = (uint64_t)7309940759667438700;
    // EBPF_OP_STXDW pc=1721 dst=r10 src=r1 offset=-80 imm=0
#line 264 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1722 dst=r1 src=r0 offset=0 imm=543649385
#line 264 "sample/undocked/map.c"
    r1 = (uint64_t)8463219665603620457;
    // EBPF_OP_STXDW pc=1724 dst=r10 src=r1 offset=-88 imm=0
#line 264 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1725 dst=r1 src=r0 offset=0 imm=2019893357
#line 264 "sample/undocked/map.c"
    r1 = (uint64_t)8386658464824631405;
    // EBPF_OP_STXDW pc=1727 dst=r10 src=r1 offset=-96 imm=0
#line 264 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1728 dst=r1 src=r0 offset=0 imm=1801807216
#line 264 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=1730 dst=r10 src=r1 offset=-104 imm=0
#line 264 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1731 dst=r1 src=r0 offset=0 imm=1600548962
#line 264 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1733 dst=r10 src=r1 offset=-112 imm=0
#line 264 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_ARSH64_IMM pc=1734 dst=r4 src=r0 offset=0 imm=32
#line 264 "sample/undocked/map.c"
    r4 = (int64_t)r4 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1735 dst=r1 src=r10 offset=0 imm=0
#line 264 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1736 dst=r1 src=r0 offset=0 imm=-112
#line 264 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=1737 dst=r2 src=r0 offset=0 imm=50
#line 264 "sample/undocked/map.c"
    r2 = IMMEDIATE(50);
    // EBPF_OP_JA pc=1738 dst=r0 src=r0 offset=60 imm=0
#line 264 "sample/undocked/map.c"
    goto label_112;
label_109:
    // EBPF_OP_LDXW pc=1739 dst=r3 src=r10 offset=-4 imm=0
#line 264 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1740 dst=r3 src=r0 offset=22 imm=1
#line 264 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(1)) {
#line 264 "sample/undocked/map.c"
        goto label_110;
#line 264 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_IMM pc=1741 dst=r1 src=r0 offset=0 imm=0
#line 264 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=1742 dst=r10 src=r1 offset=-72 imm=0
#line 264 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint8_t)r1;
    // EBPF_OP_LDDW pc=1743 dst=r1 src=r0 offset=0 imm=1852404835
#line 264 "sample/undocked/map.c"
    r1 = (uint64_t)7216209606537213027;
    // EBPF_OP_STXDW pc=1745 dst=r10 src=r1 offset=-80 imm=0
#line 264 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1746 dst=r1 src=r0 offset=0 imm=543434016
#line 264 "sample/undocked/map.c"
    r1 = (uint64_t)7309474570952779040;
    // EBPF_OP_STXDW pc=1748 dst=r10 src=r1 offset=-88 imm=0
#line 264 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1749 dst=r1 src=r0 offset=0 imm=1701978221
#line 264 "sample/undocked/map.c"
    r1 = (uint64_t)7958552634295722093;
    // EBPF_OP_STXDW pc=1751 dst=r10 src=r1 offset=-96 imm=0
#line 264 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1752 dst=r1 src=r0 offset=0 imm=1801807216
#line 264 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=1754 dst=r10 src=r1 offset=-104 imm=0
#line 264 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1755 dst=r1 src=r0 offset=0 imm=1600548962
#line 264 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1757 dst=r10 src=r1 offset=-112 imm=0
#line 264 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1758 dst=r1 src=r10 offset=0 imm=0
#line 264 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1759 dst=r1 src=r0 offset=0 imm=-112
#line 264 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=1760 dst=r2 src=r0 offset=0 imm=41
#line 264 "sample/undocked/map.c"
    r2 = IMMEDIATE(41);
    // EBPF_OP_MOV64_IMM pc=1761 dst=r4 src=r0 offset=0 imm=1
#line 264 "sample/undocked/map.c"
    r4 = IMMEDIATE(1);
    // EBPF_OP_JA pc=1762 dst=r0 src=r0 offset=-454 imm=0
#line 264 "sample/undocked/map.c"
    goto label_83;
label_110:
    // EBPF_OP_MOV64_IMM pc=1763 dst=r7 src=r0 offset=0 imm=0
#line 264 "sample/undocked/map.c"
    r7 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=1764 dst=r10 src=r7 offset=-4 imm=0
#line 272 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=1765 dst=r2 src=r10 offset=0 imm=0
#line 272 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1766 dst=r2 src=r0 offset=0 imm=-4
#line 272 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1767 dst=r1 src=r1 offset=0 imm=7
#line 272 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
    // EBPF_OP_CALL pc=1769 dst=r0 src=r0 offset=0 imm=17
#line 272 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[8].address(r1, r2, r3, r4, r5, context);
#line 272 "sample/undocked/map.c"
    if ((runtime_context->helper_data[8].tail_call) && (r0 == 0)) {
#line 272 "sample/undocked/map.c"
        return 0;
#line 272 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1770 dst=r6 src=r0 offset=0 imm=0
#line 272 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1771 dst=r4 src=r6 offset=0 imm=0
#line 272 "sample/undocked/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=1772 dst=r4 src=r0 offset=0 imm=32
#line 272 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1773 dst=r1 src=r4 offset=0 imm=0
#line 272 "sample/undocked/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=1774 dst=r1 src=r0 offset=0 imm=32
#line 272 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=1775 dst=r1 src=r0 offset=26 imm=0
#line 272 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 272 "sample/undocked/map.c"
        goto label_113;
#line 272 "sample/undocked/map.c"
    }
label_111:
    // EBPF_OP_LDDW pc=1776 dst=r1 src=r0 offset=0 imm=1701737077
#line 272 "sample/undocked/map.c"
    r1 = (uint64_t)7216209593501643381;
    // EBPF_OP_STXDW pc=1778 dst=r10 src=r1 offset=-72 imm=0
#line 272 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1779 dst=r1 src=r0 offset=0 imm=1680154740
#line 272 "sample/undocked/map.c"
    r1 = (uint64_t)8387235364492091508;
    // EBPF_OP_STXDW pc=1781 dst=r10 src=r1 offset=-80 imm=0
#line 272 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1782 dst=r1 src=r0 offset=0 imm=1914726254
#line 272 "sample/undocked/map.c"
    r1 = (uint64_t)7815279607914981230;
    // EBPF_OP_STXDW pc=1784 dst=r10 src=r1 offset=-88 imm=0
#line 272 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1785 dst=r1 src=r0 offset=0 imm=1886938400
#line 272 "sample/undocked/map.c"
    r1 = (uint64_t)7598807758610654496;
    // EBPF_OP_STXDW pc=1787 dst=r10 src=r1 offset=-96 imm=0
#line 272 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1788 dst=r1 src=r0 offset=0 imm=1601204080
#line 272 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=1790 dst=r10 src=r1 offset=-104 imm=0
#line 272 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1791 dst=r1 src=r0 offset=0 imm=1600548962
#line 272 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1793 dst=r10 src=r1 offset=-112 imm=0
#line 272 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_STXB pc=1794 dst=r10 src=r7 offset=-64 imm=0
#line 272 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint8_t)r7;
    // EBPF_OP_ARSH64_IMM pc=1795 dst=r4 src=r0 offset=0 imm=32
#line 272 "sample/undocked/map.c"
    r4 = (int64_t)r4 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1796 dst=r1 src=r10 offset=0 imm=0
#line 272 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1797 dst=r1 src=r0 offset=0 imm=-112
#line 272 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=1798 dst=r2 src=r0 offset=0 imm=49
#line 272 "sample/undocked/map.c"
    r2 = IMMEDIATE(49);
label_112:
    // EBPF_OP_MOV64_IMM pc=1799 dst=r3 src=r0 offset=0 imm=0
#line 272 "sample/undocked/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=1800 dst=r0 src=r0 offset=0 imm=14
#line 272 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[7].address(r1, r2, r3, r4, r5, context);
#line 272 "sample/undocked/map.c"
    if ((runtime_context->helper_data[7].tail_call) && (r0 == 0)) {
#line 272 "sample/undocked/map.c"
        return 0;
#line 272 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1801 dst=r0 src=r0 offset=-490 imm=0
#line 272 "sample/undocked/map.c"
    goto label_84;
label_113:
    // EBPF_OP_LDXW pc=1802 dst=r3 src=r10 offset=-4 imm=0
#line 272 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1803 dst=r3 src=r0 offset=20 imm=1
#line 272 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(1)) {
#line 272 "sample/undocked/map.c"
        goto label_114;
#line 272 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=1804 dst=r1 src=r0 offset=0 imm=1735289204
#line 272 "sample/undocked/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=1806 dst=r10 src=r1 offset=-80 imm=0
#line 272 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1807 dst=r1 src=r0 offset=0 imm=1696621605
#line 272 "sample/undocked/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=1809 dst=r10 src=r1 offset=-88 imm=0
#line 272 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1810 dst=r1 src=r0 offset=0 imm=1952805408
#line 272 "sample/undocked/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=1812 dst=r10 src=r1 offset=-96 imm=0
#line 272 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1813 dst=r1 src=r0 offset=0 imm=1601204080
#line 272 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=1815 dst=r10 src=r1 offset=-104 imm=0
#line 272 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1816 dst=r1 src=r0 offset=0 imm=1600548962
#line 272 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1818 dst=r10 src=r1 offset=-112 imm=0
#line 272 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1819 dst=r1 src=r10 offset=0 imm=0
#line 272 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1820 dst=r1 src=r0 offset=0 imm=-112
#line 272 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=1821 dst=r2 src=r0 offset=0 imm=40
#line 272 "sample/undocked/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_MOV64_IMM pc=1822 dst=r4 src=r0 offset=0 imm=1
#line 272 "sample/undocked/map.c"
    r4 = IMMEDIATE(1);
    // EBPF_OP_JA pc=1823 dst=r0 src=r0 offset=-515 imm=0
#line 272 "sample/undocked/map.c"
    goto label_83;
label_114:
    // EBPF_OP_STXW pc=1824 dst=r10 src=r7 offset=-4 imm=0
#line 273 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=1825 dst=r2 src=r10 offset=0 imm=0
#line 273 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1826 dst=r2 src=r0 offset=0 imm=-4
#line 273 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1827 dst=r1 src=r1 offset=0 imm=7
#line 273 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
    // EBPF_OP_CALL pc=1829 dst=r0 src=r0 offset=0 imm=17
#line 273 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[8].address(r1, r2, r3, r4, r5, context);
#line 273 "sample/undocked/map.c"
    if ((runtime_context->helper_data[8].tail_call) && (r0 == 0)) {
#line 273 "sample/undocked/map.c"
        return 0;
#line 273 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1830 dst=r6 src=r0 offset=0 imm=0
#line 273 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1831 dst=r4 src=r6 offset=0 imm=0
#line 273 "sample/undocked/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=1832 dst=r4 src=r0 offset=0 imm=32
#line 273 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1833 dst=r1 src=r4 offset=0 imm=0
#line 273 "sample/undocked/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=1834 dst=r1 src=r0 offset=0 imm=32
#line 273 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=1835 dst=r1 src=r0 offset=1 imm=0
#line 273 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 273 "sample/undocked/map.c"
        goto label_115;
#line 273 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1836 dst=r0 src=r0 offset=-61 imm=0
#line 273 "sample/undocked/map.c"
    goto label_111;
label_115:
    // EBPF_OP_LDXW pc=1837 dst=r3 src=r10 offset=-4 imm=0
#line 273 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1838 dst=r3 src=r0 offset=20 imm=2
#line 273 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(2)) {
#line 273 "sample/undocked/map.c"
        goto label_116;
#line 273 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=1839 dst=r1 src=r0 offset=0 imm=1735289204
#line 273 "sample/undocked/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=1841 dst=r10 src=r1 offset=-80 imm=0
#line 273 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1842 dst=r1 src=r0 offset=0 imm=1696621605
#line 273 "sample/undocked/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=1844 dst=r10 src=r1 offset=-88 imm=0
#line 273 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1845 dst=r1 src=r0 offset=0 imm=1952805408
#line 273 "sample/undocked/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=1847 dst=r10 src=r1 offset=-96 imm=0
#line 273 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1848 dst=r1 src=r0 offset=0 imm=1601204080
#line 273 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=1850 dst=r10 src=r1 offset=-104 imm=0
#line 273 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1851 dst=r1 src=r0 offset=0 imm=1600548962
#line 273 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1853 dst=r10 src=r1 offset=-112 imm=0
#line 273 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1854 dst=r1 src=r10 offset=0 imm=0
#line 273 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1855 dst=r1 src=r0 offset=0 imm=-112
#line 273 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=1856 dst=r2 src=r0 offset=0 imm=40
#line 273 "sample/undocked/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_MOV64_IMM pc=1857 dst=r4 src=r0 offset=0 imm=2
#line 273 "sample/undocked/map.c"
    r4 = IMMEDIATE(2);
    // EBPF_OP_JA pc=1858 dst=r0 src=r0 offset=-550 imm=0
#line 273 "sample/undocked/map.c"
    goto label_83;
label_116:
    // EBPF_OP_STXW pc=1859 dst=r10 src=r7 offset=-4 imm=0
#line 274 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=1860 dst=r2 src=r10 offset=0 imm=0
#line 274 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1861 dst=r2 src=r0 offset=0 imm=-4
#line 274 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1862 dst=r1 src=r1 offset=0 imm=7
#line 274 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
    // EBPF_OP_CALL pc=1864 dst=r0 src=r0 offset=0 imm=17
#line 274 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[8].address(r1, r2, r3, r4, r5, context);
#line 274 "sample/undocked/map.c"
    if ((runtime_context->helper_data[8].tail_call) && (r0 == 0)) {
#line 274 "sample/undocked/map.c"
        return 0;
#line 274 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1865 dst=r6 src=r0 offset=0 imm=0
#line 274 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1866 dst=r4 src=r6 offset=0 imm=0
#line 274 "sample/undocked/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=1867 dst=r4 src=r0 offset=0 imm=32
#line 274 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1868 dst=r1 src=r4 offset=0 imm=0
#line 274 "sample/undocked/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=1869 dst=r1 src=r0 offset=0 imm=32
#line 274 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=1870 dst=r1 src=r0 offset=1 imm=0
#line 274 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 274 "sample/undocked/map.c"
        goto label_117;
#line 274 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1871 dst=r0 src=r0 offset=-96 imm=0
#line 274 "sample/undocked/map.c"
    goto label_111;
label_117:
    // EBPF_OP_LDXW pc=1872 dst=r3 src=r10 offset=-4 imm=0
#line 274 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1873 dst=r3 src=r0 offset=20 imm=3
#line 274 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(3)) {
#line 274 "sample/undocked/map.c"
        goto label_118;
#line 274 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=1874 dst=r1 src=r0 offset=0 imm=1735289204
#line 274 "sample/undocked/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=1876 dst=r10 src=r1 offset=-80 imm=0
#line 274 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1877 dst=r1 src=r0 offset=0 imm=1696621605
#line 274 "sample/undocked/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=1879 dst=r10 src=r1 offset=-88 imm=0
#line 274 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1880 dst=r1 src=r0 offset=0 imm=1952805408
#line 274 "sample/undocked/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=1882 dst=r10 src=r1 offset=-96 imm=0
#line 274 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1883 dst=r1 src=r0 offset=0 imm=1601204080
#line 274 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=1885 dst=r10 src=r1 offset=-104 imm=0
#line 274 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1886 dst=r1 src=r0 offset=0 imm=1600548962
#line 274 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1888 dst=r10 src=r1 offset=-112 imm=0
#line 274 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1889 dst=r1 src=r10 offset=0 imm=0
#line 274 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1890 dst=r1 src=r0 offset=0 imm=-112
#line 274 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=1891 dst=r2 src=r0 offset=0 imm=40
#line 274 "sample/undocked/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_MOV64_IMM pc=1892 dst=r4 src=r0 offset=0 imm=3
#line 274 "sample/undocked/map.c"
    r4 = IMMEDIATE(3);
    // EBPF_OP_JA pc=1893 dst=r0 src=r0 offset=-585 imm=0
#line 274 "sample/undocked/map.c"
    goto label_83;
label_118:
    // EBPF_OP_STXW pc=1894 dst=r10 src=r7 offset=-4 imm=0
#line 275 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=1895 dst=r2 src=r10 offset=0 imm=0
#line 275 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1896 dst=r2 src=r0 offset=0 imm=-4
#line 275 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1897 dst=r1 src=r1 offset=0 imm=7
#line 275 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
    // EBPF_OP_CALL pc=1899 dst=r0 src=r0 offset=0 imm=17
#line 275 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[8].address(r1, r2, r3, r4, r5, context);
#line 275 "sample/undocked/map.c"
    if ((runtime_context->helper_data[8].tail_call) && (r0 == 0)) {
#line 275 "sample/undocked/map.c"
        return 0;
#line 275 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1900 dst=r6 src=r0 offset=0 imm=0
#line 275 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1901 dst=r4 src=r6 offset=0 imm=0
#line 275 "sample/undocked/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=1902 dst=r4 src=r0 offset=0 imm=32
#line 275 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1903 dst=r1 src=r4 offset=0 imm=0
#line 275 "sample/undocked/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=1904 dst=r1 src=r0 offset=0 imm=32
#line 275 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=1905 dst=r1 src=r0 offset=1 imm=0
#line 275 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 275 "sample/undocked/map.c"
        goto label_119;
#line 275 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1906 dst=r0 src=r0 offset=-131 imm=0
#line 275 "sample/undocked/map.c"
    goto label_111;
label_119:
    // EBPF_OP_LDXW pc=1907 dst=r3 src=r10 offset=-4 imm=0
#line 275 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1908 dst=r3 src=r0 offset=20 imm=4
#line 275 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(4)) {
#line 275 "sample/undocked/map.c"
        goto label_120;
#line 275 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=1909 dst=r1 src=r0 offset=0 imm=1735289204
#line 275 "sample/undocked/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=1911 dst=r10 src=r1 offset=-80 imm=0
#line 275 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1912 dst=r1 src=r0 offset=0 imm=1696621605
#line 275 "sample/undocked/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=1914 dst=r10 src=r1 offset=-88 imm=0
#line 275 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1915 dst=r1 src=r0 offset=0 imm=1952805408
#line 275 "sample/undocked/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=1917 dst=r10 src=r1 offset=-96 imm=0
#line 275 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1918 dst=r1 src=r0 offset=0 imm=1601204080
#line 275 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=1920 dst=r10 src=r1 offset=-104 imm=0
#line 275 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1921 dst=r1 src=r0 offset=0 imm=1600548962
#line 275 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1923 dst=r10 src=r1 offset=-112 imm=0
#line 275 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1924 dst=r1 src=r10 offset=0 imm=0
#line 275 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1925 dst=r1 src=r0 offset=0 imm=-112
#line 275 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=1926 dst=r2 src=r0 offset=0 imm=40
#line 275 "sample/undocked/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_MOV64_IMM pc=1927 dst=r4 src=r0 offset=0 imm=4
#line 275 "sample/undocked/map.c"
    r4 = IMMEDIATE(4);
    // EBPF_OP_JA pc=1928 dst=r0 src=r0 offset=-620 imm=0
#line 275 "sample/undocked/map.c"
    goto label_83;
label_120:
    // EBPF_OP_STXW pc=1929 dst=r10 src=r7 offset=-4 imm=0
#line 276 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=1930 dst=r2 src=r10 offset=0 imm=0
#line 276 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1931 dst=r2 src=r0 offset=0 imm=-4
#line 276 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1932 dst=r1 src=r1 offset=0 imm=7
#line 276 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
    // EBPF_OP_CALL pc=1934 dst=r0 src=r0 offset=0 imm=17
#line 276 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[8].address(r1, r2, r3, r4, r5, context);
#line 276 "sample/undocked/map.c"
    if ((runtime_context->helper_data[8].tail_call) && (r0 == 0)) {
#line 276 "sample/undocked/map.c"
        return 0;
#line 276 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1935 dst=r6 src=r0 offset=0 imm=0
#line 276 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1936 dst=r4 src=r6 offset=0 imm=0
#line 276 "sample/undocked/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=1937 dst=r4 src=r0 offset=0 imm=32
#line 276 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1938 dst=r1 src=r4 offset=0 imm=0
#line 276 "sample/undocked/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=1939 dst=r1 src=r0 offset=0 imm=32
#line 276 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=1940 dst=r1 src=r0 offset=1 imm=0
#line 276 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 276 "sample/undocked/map.c"
        goto label_121;
#line 276 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1941 dst=r0 src=r0 offset=-166 imm=0
#line 276 "sample/undocked/map.c"
    goto label_111;
label_121:
    // EBPF_OP_LDXW pc=1942 dst=r3 src=r10 offset=-4 imm=0
#line 276 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1943 dst=r3 src=r0 offset=20 imm=5
#line 276 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(5)) {
#line 276 "sample/undocked/map.c"
        goto label_122;
#line 276 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=1944 dst=r1 src=r0 offset=0 imm=1735289204
#line 276 "sample/undocked/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=1946 dst=r10 src=r1 offset=-80 imm=0
#line 276 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1947 dst=r1 src=r0 offset=0 imm=1696621605
#line 276 "sample/undocked/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=1949 dst=r10 src=r1 offset=-88 imm=0
#line 276 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1950 dst=r1 src=r0 offset=0 imm=1952805408
#line 276 "sample/undocked/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=1952 dst=r10 src=r1 offset=-96 imm=0
#line 276 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1953 dst=r1 src=r0 offset=0 imm=1601204080
#line 276 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=1955 dst=r10 src=r1 offset=-104 imm=0
#line 276 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1956 dst=r1 src=r0 offset=0 imm=1600548962
#line 276 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1958 dst=r10 src=r1 offset=-112 imm=0
#line 276 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1959 dst=r1 src=r10 offset=0 imm=0
#line 276 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1960 dst=r1 src=r0 offset=0 imm=-112
#line 276 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=1961 dst=r2 src=r0 offset=0 imm=40
#line 276 "sample/undocked/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_MOV64_IMM pc=1962 dst=r4 src=r0 offset=0 imm=5
#line 276 "sample/undocked/map.c"
    r4 = IMMEDIATE(5);
    // EBPF_OP_JA pc=1963 dst=r0 src=r0 offset=-655 imm=0
#line 276 "sample/undocked/map.c"
    goto label_83;
label_122:
    // EBPF_OP_STXW pc=1964 dst=r10 src=r7 offset=-4 imm=0
#line 277 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=1965 dst=r2 src=r10 offset=0 imm=0
#line 277 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=1966 dst=r2 src=r0 offset=0 imm=-4
#line 277 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=1967 dst=r1 src=r1 offset=0 imm=7
#line 277 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
    // EBPF_OP_CALL pc=1969 dst=r0 src=r0 offset=0 imm=17
#line 277 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[8].address(r1, r2, r3, r4, r5, context);
#line 277 "sample/undocked/map.c"
    if ((runtime_context->helper_data[8].tail_call) && (r0 == 0)) {
#line 277 "sample/undocked/map.c"
        return 0;
#line 277 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=1970 dst=r6 src=r0 offset=0 imm=0
#line 277 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=1971 dst=r4 src=r6 offset=0 imm=0
#line 277 "sample/undocked/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=1972 dst=r4 src=r0 offset=0 imm=32
#line 277 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=1973 dst=r1 src=r4 offset=0 imm=0
#line 277 "sample/undocked/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=1974 dst=r1 src=r0 offset=0 imm=32
#line 277 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=1975 dst=r1 src=r0 offset=1 imm=0
#line 277 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 277 "sample/undocked/map.c"
        goto label_123;
#line 277 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=1976 dst=r0 src=r0 offset=-201 imm=0
#line 277 "sample/undocked/map.c"
    goto label_111;
label_123:
    // EBPF_OP_LDXW pc=1977 dst=r3 src=r10 offset=-4 imm=0
#line 277 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=1978 dst=r3 src=r0 offset=20 imm=6
#line 277 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(6)) {
#line 277 "sample/undocked/map.c"
        goto label_124;
#line 277 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=1979 dst=r1 src=r0 offset=0 imm=1735289204
#line 277 "sample/undocked/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=1981 dst=r10 src=r1 offset=-80 imm=0
#line 277 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1982 dst=r1 src=r0 offset=0 imm=1696621605
#line 277 "sample/undocked/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=1984 dst=r10 src=r1 offset=-88 imm=0
#line 277 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1985 dst=r1 src=r0 offset=0 imm=1952805408
#line 277 "sample/undocked/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=1987 dst=r10 src=r1 offset=-96 imm=0
#line 277 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1988 dst=r1 src=r0 offset=0 imm=1601204080
#line 277 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=1990 dst=r10 src=r1 offset=-104 imm=0
#line 277 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=1991 dst=r1 src=r0 offset=0 imm=1600548962
#line 277 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=1993 dst=r10 src=r1 offset=-112 imm=0
#line 277 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=1994 dst=r1 src=r10 offset=0 imm=0
#line 277 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=1995 dst=r1 src=r0 offset=0 imm=-112
#line 277 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=1996 dst=r2 src=r0 offset=0 imm=40
#line 277 "sample/undocked/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_MOV64_IMM pc=1997 dst=r4 src=r0 offset=0 imm=6
#line 277 "sample/undocked/map.c"
    r4 = IMMEDIATE(6);
    // EBPF_OP_JA pc=1998 dst=r0 src=r0 offset=-690 imm=0
#line 277 "sample/undocked/map.c"
    goto label_83;
label_124:
    // EBPF_OP_STXW pc=1999 dst=r10 src=r7 offset=-4 imm=0
#line 278 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=2000 dst=r2 src=r10 offset=0 imm=0
#line 278 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2001 dst=r2 src=r0 offset=0 imm=-4
#line 278 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2002 dst=r1 src=r1 offset=0 imm=7
#line 278 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
    // EBPF_OP_CALL pc=2004 dst=r0 src=r0 offset=0 imm=17
#line 278 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[8].address(r1, r2, r3, r4, r5, context);
#line 278 "sample/undocked/map.c"
    if ((runtime_context->helper_data[8].tail_call) && (r0 == 0)) {
#line 278 "sample/undocked/map.c"
        return 0;
#line 278 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=2005 dst=r6 src=r0 offset=0 imm=0
#line 278 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=2006 dst=r4 src=r6 offset=0 imm=0
#line 278 "sample/undocked/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=2007 dst=r4 src=r0 offset=0 imm=32
#line 278 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2008 dst=r1 src=r4 offset=0 imm=0
#line 278 "sample/undocked/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=2009 dst=r1 src=r0 offset=0 imm=32
#line 278 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2010 dst=r1 src=r0 offset=1 imm=0
#line 278 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 278 "sample/undocked/map.c"
        goto label_125;
#line 278 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=2011 dst=r0 src=r0 offset=-236 imm=0
#line 278 "sample/undocked/map.c"
    goto label_111;
label_125:
    // EBPF_OP_LDXW pc=2012 dst=r3 src=r10 offset=-4 imm=0
#line 278 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=2013 dst=r3 src=r0 offset=20 imm=7
#line 278 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(7)) {
#line 278 "sample/undocked/map.c"
        goto label_126;
#line 278 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=2014 dst=r1 src=r0 offset=0 imm=1735289204
#line 278 "sample/undocked/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=2016 dst=r10 src=r1 offset=-80 imm=0
#line 278 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2017 dst=r1 src=r0 offset=0 imm=1696621605
#line 278 "sample/undocked/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=2019 dst=r10 src=r1 offset=-88 imm=0
#line 278 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2020 dst=r1 src=r0 offset=0 imm=1952805408
#line 278 "sample/undocked/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=2022 dst=r10 src=r1 offset=-96 imm=0
#line 278 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2023 dst=r1 src=r0 offset=0 imm=1601204080
#line 278 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=2025 dst=r10 src=r1 offset=-104 imm=0
#line 278 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2026 dst=r1 src=r0 offset=0 imm=1600548962
#line 278 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2028 dst=r10 src=r1 offset=-112 imm=0
#line 278 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=2029 dst=r1 src=r10 offset=0 imm=0
#line 278 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2030 dst=r1 src=r0 offset=0 imm=-112
#line 278 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=2031 dst=r2 src=r0 offset=0 imm=40
#line 278 "sample/undocked/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_MOV64_IMM pc=2032 dst=r4 src=r0 offset=0 imm=7
#line 278 "sample/undocked/map.c"
    r4 = IMMEDIATE(7);
    // EBPF_OP_JA pc=2033 dst=r0 src=r0 offset=-725 imm=0
#line 278 "sample/undocked/map.c"
    goto label_83;
label_126:
    // EBPF_OP_STXW pc=2034 dst=r10 src=r7 offset=-4 imm=0
#line 279 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=2035 dst=r2 src=r10 offset=0 imm=0
#line 279 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2036 dst=r2 src=r0 offset=0 imm=-4
#line 279 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2037 dst=r1 src=r1 offset=0 imm=7
#line 279 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
    // EBPF_OP_CALL pc=2039 dst=r0 src=r0 offset=0 imm=17
#line 279 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[8].address(r1, r2, r3, r4, r5, context);
#line 279 "sample/undocked/map.c"
    if ((runtime_context->helper_data[8].tail_call) && (r0 == 0)) {
#line 279 "sample/undocked/map.c"
        return 0;
#line 279 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=2040 dst=r6 src=r0 offset=0 imm=0
#line 279 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=2041 dst=r4 src=r6 offset=0 imm=0
#line 279 "sample/undocked/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=2042 dst=r4 src=r0 offset=0 imm=32
#line 279 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2043 dst=r1 src=r4 offset=0 imm=0
#line 279 "sample/undocked/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=2044 dst=r1 src=r0 offset=0 imm=32
#line 279 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2045 dst=r1 src=r0 offset=1 imm=0
#line 279 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 279 "sample/undocked/map.c"
        goto label_127;
#line 279 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=2046 dst=r0 src=r0 offset=-271 imm=0
#line 279 "sample/undocked/map.c"
    goto label_111;
label_127:
    // EBPF_OP_LDXW pc=2047 dst=r3 src=r10 offset=-4 imm=0
#line 279 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=2048 dst=r3 src=r0 offset=20 imm=8
#line 279 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(8)) {
#line 279 "sample/undocked/map.c"
        goto label_128;
#line 279 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=2049 dst=r1 src=r0 offset=0 imm=1735289204
#line 279 "sample/undocked/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=2051 dst=r10 src=r1 offset=-80 imm=0
#line 279 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2052 dst=r1 src=r0 offset=0 imm=1696621605
#line 279 "sample/undocked/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=2054 dst=r10 src=r1 offset=-88 imm=0
#line 279 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2055 dst=r1 src=r0 offset=0 imm=1952805408
#line 279 "sample/undocked/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=2057 dst=r10 src=r1 offset=-96 imm=0
#line 279 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2058 dst=r1 src=r0 offset=0 imm=1601204080
#line 279 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=2060 dst=r10 src=r1 offset=-104 imm=0
#line 279 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2061 dst=r1 src=r0 offset=0 imm=1600548962
#line 279 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2063 dst=r10 src=r1 offset=-112 imm=0
#line 279 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=2064 dst=r1 src=r10 offset=0 imm=0
#line 279 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2065 dst=r1 src=r0 offset=0 imm=-112
#line 279 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=2066 dst=r2 src=r0 offset=0 imm=40
#line 279 "sample/undocked/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_MOV64_IMM pc=2067 dst=r4 src=r0 offset=0 imm=8
#line 279 "sample/undocked/map.c"
    r4 = IMMEDIATE(8);
    // EBPF_OP_JA pc=2068 dst=r0 src=r0 offset=-760 imm=0
#line 279 "sample/undocked/map.c"
    goto label_83;
label_128:
    // EBPF_OP_STXW pc=2069 dst=r10 src=r7 offset=-4 imm=0
#line 280 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=2070 dst=r2 src=r10 offset=0 imm=0
#line 280 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2071 dst=r2 src=r0 offset=0 imm=-4
#line 280 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2072 dst=r1 src=r1 offset=0 imm=7
#line 280 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
    // EBPF_OP_CALL pc=2074 dst=r0 src=r0 offset=0 imm=17
#line 280 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[8].address(r1, r2, r3, r4, r5, context);
#line 280 "sample/undocked/map.c"
    if ((runtime_context->helper_data[8].tail_call) && (r0 == 0)) {
#line 280 "sample/undocked/map.c"
        return 0;
#line 280 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=2075 dst=r6 src=r0 offset=0 imm=0
#line 280 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=2076 dst=r4 src=r6 offset=0 imm=0
#line 280 "sample/undocked/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=2077 dst=r4 src=r0 offset=0 imm=32
#line 280 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2078 dst=r1 src=r4 offset=0 imm=0
#line 280 "sample/undocked/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=2079 dst=r1 src=r0 offset=0 imm=32
#line 280 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2080 dst=r1 src=r0 offset=1 imm=0
#line 280 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 280 "sample/undocked/map.c"
        goto label_129;
#line 280 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=2081 dst=r0 src=r0 offset=-306 imm=0
#line 280 "sample/undocked/map.c"
    goto label_111;
label_129:
    // EBPF_OP_LDXW pc=2082 dst=r3 src=r10 offset=-4 imm=0
#line 280 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=2083 dst=r3 src=r0 offset=20 imm=9
#line 280 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(9)) {
#line 280 "sample/undocked/map.c"
        goto label_130;
#line 280 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=2084 dst=r1 src=r0 offset=0 imm=1735289204
#line 280 "sample/undocked/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=2086 dst=r10 src=r1 offset=-80 imm=0
#line 280 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2087 dst=r1 src=r0 offset=0 imm=1696621605
#line 280 "sample/undocked/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=2089 dst=r10 src=r1 offset=-88 imm=0
#line 280 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2090 dst=r1 src=r0 offset=0 imm=1952805408
#line 280 "sample/undocked/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=2092 dst=r10 src=r1 offset=-96 imm=0
#line 280 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2093 dst=r1 src=r0 offset=0 imm=1601204080
#line 280 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=2095 dst=r10 src=r1 offset=-104 imm=0
#line 280 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2096 dst=r1 src=r0 offset=0 imm=1600548962
#line 280 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2098 dst=r10 src=r1 offset=-112 imm=0
#line 280 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=2099 dst=r1 src=r10 offset=0 imm=0
#line 280 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2100 dst=r1 src=r0 offset=0 imm=-112
#line 280 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=2101 dst=r2 src=r0 offset=0 imm=40
#line 280 "sample/undocked/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_MOV64_IMM pc=2102 dst=r4 src=r0 offset=0 imm=9
#line 280 "sample/undocked/map.c"
    r4 = IMMEDIATE(9);
    // EBPF_OP_JA pc=2103 dst=r0 src=r0 offset=-795 imm=0
#line 280 "sample/undocked/map.c"
    goto label_83;
label_130:
    // EBPF_OP_STXW pc=2104 dst=r10 src=r7 offset=-4 imm=0
#line 281 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=2105 dst=r2 src=r10 offset=0 imm=0
#line 281 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2106 dst=r2 src=r0 offset=0 imm=-4
#line 281 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2107 dst=r1 src=r1 offset=0 imm=7
#line 281 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
    // EBPF_OP_CALL pc=2109 dst=r0 src=r0 offset=0 imm=17
#line 281 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[8].address(r1, r2, r3, r4, r5, context);
#line 281 "sample/undocked/map.c"
    if ((runtime_context->helper_data[8].tail_call) && (r0 == 0)) {
#line 281 "sample/undocked/map.c"
        return 0;
#line 281 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=2110 dst=r6 src=r0 offset=0 imm=0
#line 281 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=2111 dst=r4 src=r6 offset=0 imm=0
#line 281 "sample/undocked/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=2112 dst=r4 src=r0 offset=0 imm=32
#line 281 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2113 dst=r1 src=r4 offset=0 imm=0
#line 281 "sample/undocked/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=2114 dst=r1 src=r0 offset=0 imm=32
#line 281 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2115 dst=r1 src=r0 offset=1 imm=0
#line 281 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 281 "sample/undocked/map.c"
        goto label_131;
#line 281 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=2116 dst=r0 src=r0 offset=-341 imm=0
#line 281 "sample/undocked/map.c"
    goto label_111;
label_131:
    // EBPF_OP_LDXW pc=2117 dst=r3 src=r10 offset=-4 imm=0
#line 281 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=2118 dst=r3 src=r0 offset=20 imm=10
#line 281 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(10)) {
#line 281 "sample/undocked/map.c"
        goto label_132;
#line 281 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=2119 dst=r1 src=r0 offset=0 imm=1735289204
#line 281 "sample/undocked/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=2121 dst=r10 src=r1 offset=-80 imm=0
#line 281 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2122 dst=r1 src=r0 offset=0 imm=1696621605
#line 281 "sample/undocked/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=2124 dst=r10 src=r1 offset=-88 imm=0
#line 281 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2125 dst=r1 src=r0 offset=0 imm=1952805408
#line 281 "sample/undocked/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=2127 dst=r10 src=r1 offset=-96 imm=0
#line 281 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2128 dst=r1 src=r0 offset=0 imm=1601204080
#line 281 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=2130 dst=r10 src=r1 offset=-104 imm=0
#line 281 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2131 dst=r1 src=r0 offset=0 imm=1600548962
#line 281 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2133 dst=r10 src=r1 offset=-112 imm=0
#line 281 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=2134 dst=r1 src=r10 offset=0 imm=0
#line 281 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2135 dst=r1 src=r0 offset=0 imm=-112
#line 281 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=2136 dst=r2 src=r0 offset=0 imm=40
#line 281 "sample/undocked/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_MOV64_IMM pc=2137 dst=r4 src=r0 offset=0 imm=10
#line 281 "sample/undocked/map.c"
    r4 = IMMEDIATE(10);
    // EBPF_OP_JA pc=2138 dst=r0 src=r0 offset=-830 imm=0
#line 281 "sample/undocked/map.c"
    goto label_83;
label_132:
    // EBPF_OP_MOV64_IMM pc=2139 dst=r1 src=r0 offset=0 imm=0
#line 281 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2140 dst=r10 src=r1 offset=-4 imm=0
#line 284 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=2141 dst=r2 src=r10 offset=0 imm=0
#line 284 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2142 dst=r2 src=r0 offset=0 imm=-4
#line 284 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2143 dst=r1 src=r1 offset=0 imm=7
#line 284 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
    // EBPF_OP_CALL pc=2145 dst=r0 src=r0 offset=0 imm=18
#line 284 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[6].address(r1, r2, r3, r4, r5, context);
#line 284 "sample/undocked/map.c"
    if ((runtime_context->helper_data[6].tail_call) && (r0 == 0)) {
#line 284 "sample/undocked/map.c"
        return 0;
#line 284 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=2146 dst=r6 src=r0 offset=0 imm=0
#line 284 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=2147 dst=r4 src=r6 offset=0 imm=0
#line 284 "sample/undocked/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=2148 dst=r4 src=r0 offset=0 imm=32
#line 284 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2149 dst=r1 src=r4 offset=0 imm=0
#line 284 "sample/undocked/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=2150 dst=r1 src=r0 offset=0 imm=32
#line 284 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_LDDW pc=2151 dst=r2 src=r0 offset=0 imm=-7
#line 284 "sample/undocked/map.c"
    r2 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=2153 dst=r1 src=r2 offset=1 imm=0
#line 284 "sample/undocked/map.c"
    if (r1 == r2) {
#line 284 "sample/undocked/map.c"
        goto label_133;
#line 284 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=2154 dst=r0 src=r0 offset=-896 imm=0
#line 284 "sample/undocked/map.c"
    goto label_78;
label_133:
    // EBPF_OP_LDXW pc=2155 dst=r3 src=r10 offset=-4 imm=0
#line 284 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=2156 dst=r3 src=r0 offset=1 imm=0
#line 284 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(0)) {
#line 284 "sample/undocked/map.c"
        goto label_134;
#line 284 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=2157 dst=r0 src=r0 offset=-870 imm=0
#line 284 "sample/undocked/map.c"
    goto label_81;
label_134:
    // EBPF_OP_STXW pc=2158 dst=r10 src=r7 offset=-4 imm=0
#line 285 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r7;
    // EBPF_OP_MOV64_REG pc=2159 dst=r2 src=r10 offset=0 imm=0
#line 285 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2160 dst=r2 src=r0 offset=0 imm=-4
#line 285 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2161 dst=r1 src=r1 offset=0 imm=7
#line 285 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
    // EBPF_OP_CALL pc=2163 dst=r0 src=r0 offset=0 imm=17
#line 285 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[8].address(r1, r2, r3, r4, r5, context);
#line 285 "sample/undocked/map.c"
    if ((runtime_context->helper_data[8].tail_call) && (r0 == 0)) {
#line 285 "sample/undocked/map.c"
        return 0;
#line 285 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=2164 dst=r6 src=r0 offset=0 imm=0
#line 285 "sample/undocked/map.c"
    r6 = r0;
    // EBPF_OP_MOV64_REG pc=2165 dst=r4 src=r6 offset=0 imm=0
#line 285 "sample/undocked/map.c"
    r4 = r6;
    // EBPF_OP_LSH64_IMM pc=2166 dst=r4 src=r0 offset=0 imm=32
#line 285 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2167 dst=r1 src=r4 offset=0 imm=0
#line 285 "sample/undocked/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=2168 dst=r1 src=r0 offset=0 imm=32
#line 285 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_LDDW pc=2169 dst=r2 src=r0 offset=0 imm=-7
#line 285 "sample/undocked/map.c"
    r2 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=2171 dst=r1 src=r2 offset=1 imm=0
#line 285 "sample/undocked/map.c"
    if (r1 == r2) {
#line 285 "sample/undocked/map.c"
        goto label_135;
#line 285 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=2172 dst=r0 src=r0 offset=-781 imm=0
#line 285 "sample/undocked/map.c"
    goto label_90;
label_135:
    // EBPF_OP_LDXW pc=2173 dst=r3 src=r10 offset=-4 imm=0
#line 285 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=2174 dst=r3 src=r0 offset=-858 imm=0
#line 285 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(0)) {
#line 285 "sample/undocked/map.c"
        goto label_85;
#line 285 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=2175 dst=r0 src=r0 offset=-758 imm=0
#line 285 "sample/undocked/map.c"
    goto label_92;
label_136:
    // EBPF_OP_LDXW pc=2176 dst=r3 src=r10 offset=-4 imm=0
#line 240 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=2177 dst=r3 src=r0 offset=50 imm=0
#line 240 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(0)) {
#line 240 "sample/undocked/map.c"
        goto label_141;
#line 240 "sample/undocked/map.c"
    }
label_137:
    // EBPF_OP_LDDW pc=2178 dst=r1 src=r0 offset=0 imm=1852404835
#line 240 "sample/undocked/map.c"
    r1 = (uint64_t)7216209606537213027;
    // EBPF_OP_STXDW pc=2180 dst=r10 src=r1 offset=-80 imm=0
#line 240 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2181 dst=r1 src=r0 offset=0 imm=543434016
#line 240 "sample/undocked/map.c"
    r1 = (uint64_t)7309474570952779040;
    // EBPF_OP_STXDW pc=2183 dst=r10 src=r1 offset=-88 imm=0
#line 240 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2184 dst=r1 src=r0 offset=0 imm=1701978221
#line 240 "sample/undocked/map.c"
    r1 = (uint64_t)7958552634295722093;
    // EBPF_OP_STXDW pc=2186 dst=r10 src=r1 offset=-96 imm=0
#line 240 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2187 dst=r1 src=r0 offset=0 imm=1801807216
#line 240 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=2189 dst=r10 src=r1 offset=-104 imm=0
#line 240 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2190 dst=r1 src=r0 offset=0 imm=1600548962
#line 240 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2192 dst=r10 src=r1 offset=-112 imm=0
#line 240 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_IMM pc=2193 dst=r1 src=r0 offset=0 imm=0
#line 240 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=2194 dst=r10 src=r1 offset=-72 imm=0
#line 240 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint8_t)r1;
    // EBPF_OP_MOV64_REG pc=2195 dst=r1 src=r10 offset=0 imm=0
#line 240 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2196 dst=r1 src=r0 offset=0 imm=-112
#line 240 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=2197 dst=r2 src=r0 offset=0 imm=41
#line 240 "sample/undocked/map.c"
    r2 = IMMEDIATE(41);
label_138:
    // EBPF_OP_MOV64_IMM pc=2198 dst=r4 src=r0 offset=0 imm=0
#line 240 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
label_139:
    // EBPF_OP_CALL pc=2199 dst=r0 src=r0 offset=0 imm=14
#line 240 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[7].address(r1, r2, r3, r4, r5, context);
#line 240 "sample/undocked/map.c"
    if ((runtime_context->helper_data[7].tail_call) && (r0 == 0)) {
#line 240 "sample/undocked/map.c"
        return 0;
#line 240 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=2200 dst=r7 src=r0 offset=0 imm=-1
#line 240 "sample/undocked/map.c"
    r7 = (uint64_t)4294967295;
label_140:
    // EBPF_OP_MOV64_IMM pc=2202 dst=r6 src=r0 offset=0 imm=0
#line 240 "sample/undocked/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_MOV64_REG pc=2203 dst=r3 src=r7 offset=0 imm=0
#line 304 "sample/undocked/map.c"
    r3 = r7;
    // EBPF_OP_LSH64_IMM pc=2204 dst=r3 src=r0 offset=0 imm=32
#line 304 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_ARSH64_IMM pc=2205 dst=r3 src=r0 offset=0 imm=32
#line 304 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_JSGT_IMM pc=2206 dst=r3 src=r0 offset=-2105 imm=-1
#line 304 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 304 "sample/undocked/map.c"
        goto label_9;
#line 304 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=2207 dst=r1 src=r0 offset=0 imm=1684369010
#line 304 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
    // EBPF_OP_STXDW pc=2209 dst=r10 src=r1 offset=-80 imm=0
#line 304 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2210 dst=r1 src=r0 offset=0 imm=541803329
#line 304 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140578485057;
    // EBPF_OP_STXDW pc=2212 dst=r10 src=r1 offset=-88 imm=0
#line 304 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2213 dst=r1 src=r0 offset=0 imm=1634541682
#line 304 "sample/undocked/map.c"
    r1 = (uint64_t)6076235989295898738;
    // EBPF_OP_STXDW pc=2215 dst=r10 src=r1 offset=-96 imm=0
#line 304 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2216 dst=r1 src=r0 offset=0 imm=1330667336
#line 304 "sample/undocked/map.c"
    r1 = (uint64_t)8027138915134627656;
    // EBPF_OP_STXDW pc=2218 dst=r10 src=r1 offset=-104 imm=0
#line 304 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2219 dst=r1 src=r0 offset=0 imm=1953719636
#line 304 "sample/undocked/map.c"
    r1 = (uint64_t)6004793778491319636;
    // EBPF_OP_STXDW pc=2221 dst=r10 src=r1 offset=-112 imm=0
#line 304 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=2222 dst=r1 src=r10 offset=0 imm=0
#line 304 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2223 dst=r1 src=r0 offset=0 imm=-112
#line 304 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=2224 dst=r2 src=r0 offset=0 imm=40
#line 304 "sample/undocked/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_CALL pc=2225 dst=r0 src=r0 offset=0 imm=13
#line 304 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 304 "sample/undocked/map.c"
    if ((runtime_context->helper_data[4].tail_call) && (r0 == 0)) {
#line 304 "sample/undocked/map.c"
        return 0;
#line 304 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=2226 dst=r6 src=r7 offset=0 imm=0
#line 304 "sample/undocked/map.c"
    r6 = r7;
    // EBPF_OP_JA pc=2227 dst=r0 src=r0 offset=-2126 imm=0
#line 304 "sample/undocked/map.c"
    goto label_9;
label_141:
    // EBPF_OP_MOV64_IMM pc=2228 dst=r6 src=r0 offset=0 imm=0
#line 304 "sample/undocked/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2229 dst=r10 src=r6 offset=-4 imm=0
#line 241 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=2230 dst=r2 src=r10 offset=0 imm=0
#line 241 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2231 dst=r2 src=r0 offset=0 imm=-4
#line 241 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2232 dst=r1 src=r1 offset=0 imm=8
#line 241 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_CALL pc=2234 dst=r0 src=r0 offset=0 imm=17
#line 241 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[8].address(r1, r2, r3, r4, r5, context);
#line 241 "sample/undocked/map.c"
    if ((runtime_context->helper_data[8].tail_call) && (r0 == 0)) {
#line 241 "sample/undocked/map.c"
        return 0;
#line 241 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=2235 dst=r7 src=r0 offset=0 imm=0
#line 241 "sample/undocked/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2236 dst=r4 src=r7 offset=0 imm=0
#line 241 "sample/undocked/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=2237 dst=r4 src=r0 offset=0 imm=32
#line 241 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2238 dst=r1 src=r4 offset=0 imm=0
#line 241 "sample/undocked/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=2239 dst=r1 src=r0 offset=0 imm=32
#line 241 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_LDDW pc=2240 dst=r2 src=r0 offset=0 imm=-7
#line 241 "sample/undocked/map.c"
    r2 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=2242 dst=r1 src=r2 offset=24 imm=0
#line 241 "sample/undocked/map.c"
    if (r1 == r2) {
#line 241 "sample/undocked/map.c"
        goto label_143;
#line 241 "sample/undocked/map.c"
    }
label_142:
    // EBPF_OP_STXB pc=2243 dst=r10 src=r6 offset=-64 imm=0
#line 241 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint8_t)r6;
    // EBPF_OP_LDDW pc=2244 dst=r1 src=r0 offset=0 imm=1701737077
#line 241 "sample/undocked/map.c"
    r1 = (uint64_t)7216209593501643381;
    // EBPF_OP_STXDW pc=2246 dst=r10 src=r1 offset=-72 imm=0
#line 241 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2247 dst=r1 src=r0 offset=0 imm=1680154740
#line 241 "sample/undocked/map.c"
    r1 = (uint64_t)8387235364492091508;
    // EBPF_OP_STXDW pc=2249 dst=r10 src=r1 offset=-80 imm=0
#line 241 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2250 dst=r1 src=r0 offset=0 imm=1914726254
#line 241 "sample/undocked/map.c"
    r1 = (uint64_t)7815279607914981230;
    // EBPF_OP_STXDW pc=2252 dst=r10 src=r1 offset=-88 imm=0
#line 241 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2253 dst=r1 src=r0 offset=0 imm=1886938400
#line 241 "sample/undocked/map.c"
    r1 = (uint64_t)7598807758610654496;
    // EBPF_OP_STXDW pc=2255 dst=r10 src=r1 offset=-96 imm=0
#line 241 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2256 dst=r1 src=r0 offset=0 imm=1601204080
#line 241 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=2258 dst=r10 src=r1 offset=-104 imm=0
#line 241 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2259 dst=r1 src=r0 offset=0 imm=1600548962
#line 241 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2261 dst=r10 src=r1 offset=-112 imm=0
#line 241 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_ARSH64_IMM pc=2262 dst=r4 src=r0 offset=0 imm=32
#line 241 "sample/undocked/map.c"
    r4 = (int64_t)r4 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2263 dst=r1 src=r10 offset=0 imm=0
#line 241 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2264 dst=r1 src=r0 offset=0 imm=-112
#line 241 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=2265 dst=r2 src=r0 offset=0 imm=49
#line 241 "sample/undocked/map.c"
    r2 = IMMEDIATE(49);
    // EBPF_OP_JA pc=2266 dst=r0 src=r0 offset=-911 imm=0
#line 241 "sample/undocked/map.c"
    goto label_87;
label_143:
    // EBPF_OP_LDXW pc=2267 dst=r3 src=r10 offset=-4 imm=0
#line 241 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=2268 dst=r3 src=r0 offset=19 imm=0
#line 241 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(0)) {
#line 241 "sample/undocked/map.c"
        goto label_145;
#line 241 "sample/undocked/map.c"
    }
label_144:
    // EBPF_OP_LDDW pc=2269 dst=r1 src=r0 offset=0 imm=1735289204
#line 241 "sample/undocked/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=2271 dst=r10 src=r1 offset=-80 imm=0
#line 241 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2272 dst=r1 src=r0 offset=0 imm=1696621605
#line 241 "sample/undocked/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=2274 dst=r10 src=r1 offset=-88 imm=0
#line 241 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2275 dst=r1 src=r0 offset=0 imm=1952805408
#line 241 "sample/undocked/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=2277 dst=r10 src=r1 offset=-96 imm=0
#line 241 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2278 dst=r1 src=r0 offset=0 imm=1601204080
#line 241 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=2280 dst=r10 src=r1 offset=-104 imm=0
#line 241 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2281 dst=r1 src=r0 offset=0 imm=1600548962
#line 241 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2283 dst=r10 src=r1 offset=-112 imm=0
#line 241 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=2284 dst=r1 src=r10 offset=0 imm=0
#line 241 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2285 dst=r1 src=r0 offset=0 imm=-112
#line 241 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=2286 dst=r2 src=r0 offset=0 imm=40
#line 241 "sample/undocked/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_JA pc=2287 dst=r0 src=r0 offset=-90 imm=0
#line 241 "sample/undocked/map.c"
    goto label_138;
label_145:
    // EBPF_OP_STXW pc=2288 dst=r10 src=r6 offset=-4 imm=0
#line 249 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=2289 dst=r2 src=r10 offset=0 imm=0
#line 249 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2290 dst=r2 src=r0 offset=0 imm=-4
#line 249 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2291 dst=r1 src=r1 offset=0 imm=8
#line 249 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_MOV64_IMM pc=2293 dst=r3 src=r0 offset=0 imm=0
#line 249 "sample/undocked/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=2294 dst=r0 src=r0 offset=0 imm=16
#line 249 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[9].address(r1, r2, r3, r4, r5, context);
#line 249 "sample/undocked/map.c"
    if ((runtime_context->helper_data[9].tail_call) && (r0 == 0)) {
#line 249 "sample/undocked/map.c"
        return 0;
#line 249 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=2295 dst=r7 src=r0 offset=0 imm=0
#line 249 "sample/undocked/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2296 dst=r5 src=r7 offset=0 imm=0
#line 249 "sample/undocked/map.c"
    r5 = r7;
    // EBPF_OP_LSH64_IMM pc=2297 dst=r5 src=r0 offset=0 imm=32
#line 249 "sample/undocked/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2298 dst=r1 src=r5 offset=0 imm=0
#line 249 "sample/undocked/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=2299 dst=r1 src=r0 offset=0 imm=32
#line 249 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2300 dst=r1 src=r0 offset=31 imm=0
#line 249 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 249 "sample/undocked/map.c"
        goto label_149;
#line 249 "sample/undocked/map.c"
    }
label_146:
    // EBPF_OP_MOV64_IMM pc=2301 dst=r1 src=r0 offset=0 imm=25637
#line 249 "sample/undocked/map.c"
    r1 = IMMEDIATE(25637);
    // EBPF_OP_STXH pc=2302 dst=r10 src=r1 offset=-60 imm=0
#line 249 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-60)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=2303 dst=r1 src=r0 offset=0 imm=543450478
#line 249 "sample/undocked/map.c"
    r1 = IMMEDIATE(543450478);
    // EBPF_OP_STXW pc=2304 dst=r10 src=r1 offset=-64 imm=0
#line 249 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=2305 dst=r1 src=r0 offset=0 imm=1914725413
#line 249 "sample/undocked/map.c"
    r1 = (uint64_t)8247626271654175781;
    // EBPF_OP_STXDW pc=2307 dst=r10 src=r1 offset=-72 imm=0
#line 249 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2308 dst=r1 src=r0 offset=0 imm=1667592312
#line 249 "sample/undocked/map.c"
    r1 = (uint64_t)2334102057442963576;
    // EBPF_OP_STXDW pc=2310 dst=r10 src=r1 offset=-80 imm=0
#line 249 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2311 dst=r1 src=r0 offset=0 imm=543649385
#line 249 "sample/undocked/map.c"
    r1 = (uint64_t)7286934307705679465;
    // EBPF_OP_STXDW pc=2313 dst=r10 src=r1 offset=-88 imm=0
#line 249 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2314 dst=r1 src=r0 offset=0 imm=1852383341
#line 249 "sample/undocked/map.c"
    r1 = (uint64_t)8390880602192683117;
    // EBPF_OP_STXDW pc=2316 dst=r10 src=r1 offset=-96 imm=0
#line 249 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2317 dst=r1 src=r0 offset=0 imm=1752397168
#line 249 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755764168048;
    // EBPF_OP_STXDW pc=2319 dst=r10 src=r1 offset=-104 imm=0
#line 249 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2320 dst=r1 src=r0 offset=0 imm=1600548962
#line 249 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2322 dst=r10 src=r1 offset=-112 imm=0
#line 249 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_STXB pc=2323 dst=r10 src=r6 offset=-58 imm=0
#line 249 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-58)) = (uint8_t)r6;
label_147:
    // EBPF_OP_LDXW pc=2324 dst=r3 src=r10 offset=-4 imm=0
#line 249 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_ARSH64_IMM pc=2325 dst=r5 src=r0 offset=0 imm=32
#line 249 "sample/undocked/map.c"
    r5 = (int64_t)r5 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2326 dst=r1 src=r10 offset=0 imm=0
#line 249 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2327 dst=r1 src=r0 offset=0 imm=-112
#line 249 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=2328 dst=r2 src=r0 offset=0 imm=55
#line 249 "sample/undocked/map.c"
    r2 = IMMEDIATE(55);
    // EBPF_OP_MOV64_IMM pc=2329 dst=r4 src=r0 offset=0 imm=0
#line 249 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
label_148:
    // EBPF_OP_CALL pc=2330 dst=r0 src=r0 offset=0 imm=15
#line 249 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[10].address(r1, r2, r3, r4, r5, context);
#line 249 "sample/undocked/map.c"
    if ((runtime_context->helper_data[10].tail_call) && (r0 == 0)) {
#line 249 "sample/undocked/map.c"
        return 0;
#line 249 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=2331 dst=r0 src=r0 offset=-130 imm=0
#line 249 "sample/undocked/map.c"
    goto label_140;
label_149:
    // EBPF_OP_MOV64_IMM pc=2332 dst=r1 src=r0 offset=0 imm=1
#line 249 "sample/undocked/map.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=2333 dst=r10 src=r1 offset=-4 imm=0
#line 250 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=2334 dst=r2 src=r10 offset=0 imm=0
#line 250 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2335 dst=r2 src=r0 offset=0 imm=-4
#line 250 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2336 dst=r1 src=r1 offset=0 imm=8
#line 250 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_MOV64_IMM pc=2338 dst=r3 src=r0 offset=0 imm=0
#line 250 "sample/undocked/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=2339 dst=r0 src=r0 offset=0 imm=16
#line 250 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[9].address(r1, r2, r3, r4, r5, context);
#line 250 "sample/undocked/map.c"
    if ((runtime_context->helper_data[9].tail_call) && (r0 == 0)) {
#line 250 "sample/undocked/map.c"
        return 0;
#line 250 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=2340 dst=r7 src=r0 offset=0 imm=0
#line 250 "sample/undocked/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2341 dst=r5 src=r7 offset=0 imm=0
#line 250 "sample/undocked/map.c"
    r5 = r7;
    // EBPF_OP_LSH64_IMM pc=2342 dst=r5 src=r0 offset=0 imm=32
#line 250 "sample/undocked/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2343 dst=r1 src=r5 offset=0 imm=0
#line 250 "sample/undocked/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=2344 dst=r1 src=r0 offset=0 imm=32
#line 250 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2345 dst=r1 src=r0 offset=1 imm=0
#line 250 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 250 "sample/undocked/map.c"
        goto label_150;
#line 250 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=2346 dst=r0 src=r0 offset=-46 imm=0
#line 250 "sample/undocked/map.c"
    goto label_146;
label_150:
    // EBPF_OP_MOV64_IMM pc=2347 dst=r1 src=r0 offset=0 imm=2
#line 250 "sample/undocked/map.c"
    r1 = IMMEDIATE(2);
    // EBPF_OP_STXW pc=2348 dst=r10 src=r1 offset=-4 imm=0
#line 251 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=2349 dst=r2 src=r10 offset=0 imm=0
#line 251 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2350 dst=r2 src=r0 offset=0 imm=-4
#line 251 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2351 dst=r1 src=r1 offset=0 imm=8
#line 251 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_MOV64_IMM pc=2353 dst=r3 src=r0 offset=0 imm=0
#line 251 "sample/undocked/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=2354 dst=r0 src=r0 offset=0 imm=16
#line 251 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[9].address(r1, r2, r3, r4, r5, context);
#line 251 "sample/undocked/map.c"
    if ((runtime_context->helper_data[9].tail_call) && (r0 == 0)) {
#line 251 "sample/undocked/map.c"
        return 0;
#line 251 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=2355 dst=r7 src=r0 offset=0 imm=0
#line 251 "sample/undocked/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2356 dst=r5 src=r7 offset=0 imm=0
#line 251 "sample/undocked/map.c"
    r5 = r7;
    // EBPF_OP_LSH64_IMM pc=2357 dst=r5 src=r0 offset=0 imm=32
#line 251 "sample/undocked/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2358 dst=r1 src=r5 offset=0 imm=0
#line 251 "sample/undocked/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=2359 dst=r1 src=r0 offset=0 imm=32
#line 251 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2360 dst=r1 src=r0 offset=1 imm=0
#line 251 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 251 "sample/undocked/map.c"
        goto label_151;
#line 251 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=2361 dst=r0 src=r0 offset=-61 imm=0
#line 251 "sample/undocked/map.c"
    goto label_146;
label_151:
    // EBPF_OP_MOV64_IMM pc=2362 dst=r1 src=r0 offset=0 imm=3
#line 251 "sample/undocked/map.c"
    r1 = IMMEDIATE(3);
    // EBPF_OP_STXW pc=2363 dst=r10 src=r1 offset=-4 imm=0
#line 252 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=2364 dst=r2 src=r10 offset=0 imm=0
#line 252 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2365 dst=r2 src=r0 offset=0 imm=-4
#line 252 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2366 dst=r1 src=r1 offset=0 imm=8
#line 252 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_MOV64_IMM pc=2368 dst=r3 src=r0 offset=0 imm=0
#line 252 "sample/undocked/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=2369 dst=r0 src=r0 offset=0 imm=16
#line 252 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[9].address(r1, r2, r3, r4, r5, context);
#line 252 "sample/undocked/map.c"
    if ((runtime_context->helper_data[9].tail_call) && (r0 == 0)) {
#line 252 "sample/undocked/map.c"
        return 0;
#line 252 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=2370 dst=r7 src=r0 offset=0 imm=0
#line 252 "sample/undocked/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2371 dst=r5 src=r7 offset=0 imm=0
#line 252 "sample/undocked/map.c"
    r5 = r7;
    // EBPF_OP_LSH64_IMM pc=2372 dst=r5 src=r0 offset=0 imm=32
#line 252 "sample/undocked/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2373 dst=r1 src=r5 offset=0 imm=0
#line 252 "sample/undocked/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=2374 dst=r1 src=r0 offset=0 imm=32
#line 252 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2375 dst=r1 src=r0 offset=1 imm=0
#line 252 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 252 "sample/undocked/map.c"
        goto label_152;
#line 252 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=2376 dst=r0 src=r0 offset=-76 imm=0
#line 252 "sample/undocked/map.c"
    goto label_146;
label_152:
    // EBPF_OP_MOV64_IMM pc=2377 dst=r1 src=r0 offset=0 imm=4
#line 252 "sample/undocked/map.c"
    r1 = IMMEDIATE(4);
    // EBPF_OP_STXW pc=2378 dst=r10 src=r1 offset=-4 imm=0
#line 253 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=2379 dst=r2 src=r10 offset=0 imm=0
#line 253 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2380 dst=r2 src=r0 offset=0 imm=-4
#line 253 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2381 dst=r1 src=r1 offset=0 imm=8
#line 253 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_MOV64_IMM pc=2383 dst=r3 src=r0 offset=0 imm=0
#line 253 "sample/undocked/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=2384 dst=r0 src=r0 offset=0 imm=16
#line 253 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[9].address(r1, r2, r3, r4, r5, context);
#line 253 "sample/undocked/map.c"
    if ((runtime_context->helper_data[9].tail_call) && (r0 == 0)) {
#line 253 "sample/undocked/map.c"
        return 0;
#line 253 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=2385 dst=r7 src=r0 offset=0 imm=0
#line 253 "sample/undocked/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2386 dst=r5 src=r7 offset=0 imm=0
#line 253 "sample/undocked/map.c"
    r5 = r7;
    // EBPF_OP_LSH64_IMM pc=2387 dst=r5 src=r0 offset=0 imm=32
#line 253 "sample/undocked/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2388 dst=r1 src=r5 offset=0 imm=0
#line 253 "sample/undocked/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=2389 dst=r1 src=r0 offset=0 imm=32
#line 253 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2390 dst=r1 src=r0 offset=1 imm=0
#line 253 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 253 "sample/undocked/map.c"
        goto label_153;
#line 253 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=2391 dst=r0 src=r0 offset=-91 imm=0
#line 253 "sample/undocked/map.c"
    goto label_146;
label_153:
    // EBPF_OP_MOV64_IMM pc=2392 dst=r1 src=r0 offset=0 imm=5
#line 253 "sample/undocked/map.c"
    r1 = IMMEDIATE(5);
    // EBPF_OP_STXW pc=2393 dst=r10 src=r1 offset=-4 imm=0
#line 254 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=2394 dst=r2 src=r10 offset=0 imm=0
#line 254 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2395 dst=r2 src=r0 offset=0 imm=-4
#line 254 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2396 dst=r1 src=r1 offset=0 imm=8
#line 254 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_MOV64_IMM pc=2398 dst=r3 src=r0 offset=0 imm=0
#line 254 "sample/undocked/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=2399 dst=r0 src=r0 offset=0 imm=16
#line 254 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[9].address(r1, r2, r3, r4, r5, context);
#line 254 "sample/undocked/map.c"
    if ((runtime_context->helper_data[9].tail_call) && (r0 == 0)) {
#line 254 "sample/undocked/map.c"
        return 0;
#line 254 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=2400 dst=r7 src=r0 offset=0 imm=0
#line 254 "sample/undocked/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2401 dst=r5 src=r7 offset=0 imm=0
#line 254 "sample/undocked/map.c"
    r5 = r7;
    // EBPF_OP_LSH64_IMM pc=2402 dst=r5 src=r0 offset=0 imm=32
#line 254 "sample/undocked/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2403 dst=r1 src=r5 offset=0 imm=0
#line 254 "sample/undocked/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=2404 dst=r1 src=r0 offset=0 imm=32
#line 254 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2405 dst=r1 src=r0 offset=1 imm=0
#line 254 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 254 "sample/undocked/map.c"
        goto label_154;
#line 254 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=2406 dst=r0 src=r0 offset=-106 imm=0
#line 254 "sample/undocked/map.c"
    goto label_146;
label_154:
    // EBPF_OP_MOV64_IMM pc=2407 dst=r1 src=r0 offset=0 imm=6
#line 254 "sample/undocked/map.c"
    r1 = IMMEDIATE(6);
    // EBPF_OP_STXW pc=2408 dst=r10 src=r1 offset=-4 imm=0
#line 255 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=2409 dst=r2 src=r10 offset=0 imm=0
#line 255 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2410 dst=r2 src=r0 offset=0 imm=-4
#line 255 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2411 dst=r1 src=r1 offset=0 imm=8
#line 255 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_MOV64_IMM pc=2413 dst=r3 src=r0 offset=0 imm=0
#line 255 "sample/undocked/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=2414 dst=r0 src=r0 offset=0 imm=16
#line 255 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[9].address(r1, r2, r3, r4, r5, context);
#line 255 "sample/undocked/map.c"
    if ((runtime_context->helper_data[9].tail_call) && (r0 == 0)) {
#line 255 "sample/undocked/map.c"
        return 0;
#line 255 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=2415 dst=r7 src=r0 offset=0 imm=0
#line 255 "sample/undocked/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2416 dst=r5 src=r7 offset=0 imm=0
#line 255 "sample/undocked/map.c"
    r5 = r7;
    // EBPF_OP_LSH64_IMM pc=2417 dst=r5 src=r0 offset=0 imm=32
#line 255 "sample/undocked/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2418 dst=r1 src=r5 offset=0 imm=0
#line 255 "sample/undocked/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=2419 dst=r1 src=r0 offset=0 imm=32
#line 255 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2420 dst=r1 src=r0 offset=1 imm=0
#line 255 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 255 "sample/undocked/map.c"
        goto label_155;
#line 255 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=2421 dst=r0 src=r0 offset=-121 imm=0
#line 255 "sample/undocked/map.c"
    goto label_146;
label_155:
    // EBPF_OP_MOV64_IMM pc=2422 dst=r1 src=r0 offset=0 imm=7
#line 255 "sample/undocked/map.c"
    r1 = IMMEDIATE(7);
    // EBPF_OP_STXW pc=2423 dst=r10 src=r1 offset=-4 imm=0
#line 256 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=2424 dst=r2 src=r10 offset=0 imm=0
#line 256 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2425 dst=r2 src=r0 offset=0 imm=-4
#line 256 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2426 dst=r1 src=r1 offset=0 imm=8
#line 256 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_MOV64_IMM pc=2428 dst=r3 src=r0 offset=0 imm=0
#line 256 "sample/undocked/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=2429 dst=r0 src=r0 offset=0 imm=16
#line 256 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[9].address(r1, r2, r3, r4, r5, context);
#line 256 "sample/undocked/map.c"
    if ((runtime_context->helper_data[9].tail_call) && (r0 == 0)) {
#line 256 "sample/undocked/map.c"
        return 0;
#line 256 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=2430 dst=r7 src=r0 offset=0 imm=0
#line 256 "sample/undocked/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2431 dst=r5 src=r7 offset=0 imm=0
#line 256 "sample/undocked/map.c"
    r5 = r7;
    // EBPF_OP_LSH64_IMM pc=2432 dst=r5 src=r0 offset=0 imm=32
#line 256 "sample/undocked/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2433 dst=r1 src=r5 offset=0 imm=0
#line 256 "sample/undocked/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=2434 dst=r1 src=r0 offset=0 imm=32
#line 256 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2435 dst=r1 src=r0 offset=1 imm=0
#line 256 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 256 "sample/undocked/map.c"
        goto label_156;
#line 256 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=2436 dst=r0 src=r0 offset=-136 imm=0
#line 256 "sample/undocked/map.c"
    goto label_146;
label_156:
    // EBPF_OP_MOV64_IMM pc=2437 dst=r1 src=r0 offset=0 imm=8
#line 256 "sample/undocked/map.c"
    r1 = IMMEDIATE(8);
    // EBPF_OP_STXW pc=2438 dst=r10 src=r1 offset=-4 imm=0
#line 257 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=2439 dst=r2 src=r10 offset=0 imm=0
#line 257 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2440 dst=r2 src=r0 offset=0 imm=-4
#line 257 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2441 dst=r1 src=r1 offset=0 imm=8
#line 257 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_MOV64_IMM pc=2443 dst=r3 src=r0 offset=0 imm=0
#line 257 "sample/undocked/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=2444 dst=r0 src=r0 offset=0 imm=16
#line 257 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[9].address(r1, r2, r3, r4, r5, context);
#line 257 "sample/undocked/map.c"
    if ((runtime_context->helper_data[9].tail_call) && (r0 == 0)) {
#line 257 "sample/undocked/map.c"
        return 0;
#line 257 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=2445 dst=r7 src=r0 offset=0 imm=0
#line 257 "sample/undocked/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2446 dst=r5 src=r7 offset=0 imm=0
#line 257 "sample/undocked/map.c"
    r5 = r7;
    // EBPF_OP_LSH64_IMM pc=2447 dst=r5 src=r0 offset=0 imm=32
#line 257 "sample/undocked/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2448 dst=r1 src=r5 offset=0 imm=0
#line 257 "sample/undocked/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=2449 dst=r1 src=r0 offset=0 imm=32
#line 257 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2450 dst=r1 src=r0 offset=1 imm=0
#line 257 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 257 "sample/undocked/map.c"
        goto label_157;
#line 257 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=2451 dst=r0 src=r0 offset=-151 imm=0
#line 257 "sample/undocked/map.c"
    goto label_146;
label_157:
    // EBPF_OP_MOV64_IMM pc=2452 dst=r1 src=r0 offset=0 imm=9
#line 257 "sample/undocked/map.c"
    r1 = IMMEDIATE(9);
    // EBPF_OP_STXW pc=2453 dst=r10 src=r1 offset=-4 imm=0
#line 258 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=2454 dst=r2 src=r10 offset=0 imm=0
#line 258 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2455 dst=r2 src=r0 offset=0 imm=-4
#line 258 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2456 dst=r1 src=r1 offset=0 imm=8
#line 258 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_MOV64_IMM pc=2458 dst=r3 src=r0 offset=0 imm=0
#line 258 "sample/undocked/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=2459 dst=r0 src=r0 offset=0 imm=16
#line 258 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[9].address(r1, r2, r3, r4, r5, context);
#line 258 "sample/undocked/map.c"
    if ((runtime_context->helper_data[9].tail_call) && (r0 == 0)) {
#line 258 "sample/undocked/map.c"
        return 0;
#line 258 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=2460 dst=r7 src=r0 offset=0 imm=0
#line 258 "sample/undocked/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2461 dst=r5 src=r7 offset=0 imm=0
#line 258 "sample/undocked/map.c"
    r5 = r7;
    // EBPF_OP_LSH64_IMM pc=2462 dst=r5 src=r0 offset=0 imm=32
#line 258 "sample/undocked/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2463 dst=r1 src=r5 offset=0 imm=0
#line 258 "sample/undocked/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=2464 dst=r1 src=r0 offset=0 imm=32
#line 258 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2465 dst=r1 src=r0 offset=1 imm=0
#line 258 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 258 "sample/undocked/map.c"
        goto label_158;
#line 258 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=2466 dst=r0 src=r0 offset=-166 imm=0
#line 258 "sample/undocked/map.c"
    goto label_146;
label_158:
    // EBPF_OP_MOV64_IMM pc=2467 dst=r6 src=r0 offset=0 imm=10
#line 258 "sample/undocked/map.c"
    r6 = IMMEDIATE(10);
    // EBPF_OP_STXW pc=2468 dst=r10 src=r6 offset=-4 imm=0
#line 261 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=2469 dst=r2 src=r10 offset=0 imm=0
#line 261 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2470 dst=r2 src=r0 offset=0 imm=-4
#line 261 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_MOV64_IMM pc=2471 dst=r8 src=r0 offset=0 imm=0
#line 261 "sample/undocked/map.c"
    r8 = IMMEDIATE(0);
    // EBPF_OP_LDDW pc=2472 dst=r1 src=r1 offset=0 imm=8
#line 261 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_MOV64_IMM pc=2474 dst=r3 src=r0 offset=0 imm=0
#line 261 "sample/undocked/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=2475 dst=r0 src=r0 offset=0 imm=16
#line 261 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[9].address(r1, r2, r3, r4, r5, context);
#line 261 "sample/undocked/map.c"
    if ((runtime_context->helper_data[9].tail_call) && (r0 == 0)) {
#line 261 "sample/undocked/map.c"
        return 0;
#line 261 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=2476 dst=r7 src=r0 offset=0 imm=0
#line 261 "sample/undocked/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2477 dst=r5 src=r7 offset=0 imm=0
#line 261 "sample/undocked/map.c"
    r5 = r7;
    // EBPF_OP_LSH64_IMM pc=2478 dst=r5 src=r0 offset=0 imm=32
#line 261 "sample/undocked/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2479 dst=r1 src=r5 offset=0 imm=0
#line 261 "sample/undocked/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=2480 dst=r1 src=r0 offset=0 imm=32
#line 261 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_LDDW pc=2481 dst=r2 src=r0 offset=0 imm=-29
#line 261 "sample/undocked/map.c"
    r2 = (uint64_t)4294967267;
    // EBPF_OP_JEQ_REG pc=2483 dst=r1 src=r2 offset=30 imm=0
#line 261 "sample/undocked/map.c"
    if (r1 == r2) {
#line 261 "sample/undocked/map.c"
        goto label_159;
#line 261 "sample/undocked/map.c"
    }
    // EBPF_OP_STXB pc=2484 dst=r10 src=r8 offset=-58 imm=0
#line 261 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-58)) = (uint8_t)r8;
    // EBPF_OP_MOV64_IMM pc=2485 dst=r1 src=r0 offset=0 imm=25637
#line 261 "sample/undocked/map.c"
    r1 = IMMEDIATE(25637);
    // EBPF_OP_STXH pc=2486 dst=r10 src=r1 offset=-60 imm=0
#line 261 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-60)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=2487 dst=r1 src=r0 offset=0 imm=543450478
#line 261 "sample/undocked/map.c"
    r1 = IMMEDIATE(543450478);
    // EBPF_OP_STXW pc=2488 dst=r10 src=r1 offset=-64 imm=0
#line 261 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=2489 dst=r1 src=r0 offset=0 imm=1914725413
#line 261 "sample/undocked/map.c"
    r1 = (uint64_t)8247626271654175781;
    // EBPF_OP_STXDW pc=2491 dst=r10 src=r1 offset=-72 imm=0
#line 261 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2492 dst=r1 src=r0 offset=0 imm=1667592312
#line 261 "sample/undocked/map.c"
    r1 = (uint64_t)2334102057442963576;
    // EBPF_OP_STXDW pc=2494 dst=r10 src=r1 offset=-80 imm=0
#line 261 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2495 dst=r1 src=r0 offset=0 imm=543649385
#line 261 "sample/undocked/map.c"
    r1 = (uint64_t)7286934307705679465;
    // EBPF_OP_STXDW pc=2497 dst=r10 src=r1 offset=-88 imm=0
#line 261 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2498 dst=r1 src=r0 offset=0 imm=1852383341
#line 261 "sample/undocked/map.c"
    r1 = (uint64_t)8390880602192683117;
    // EBPF_OP_STXDW pc=2500 dst=r10 src=r1 offset=-96 imm=0
#line 261 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2501 dst=r1 src=r0 offset=0 imm=1752397168
#line 261 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755764168048;
    // EBPF_OP_STXDW pc=2503 dst=r10 src=r1 offset=-104 imm=0
#line 261 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2504 dst=r1 src=r0 offset=0 imm=1600548962
#line 261 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2506 dst=r10 src=r1 offset=-112 imm=0
#line 261 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_LDXW pc=2507 dst=r3 src=r10 offset=-4 imm=0
#line 261 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_ARSH64_IMM pc=2508 dst=r5 src=r0 offset=0 imm=32
#line 261 "sample/undocked/map.c"
    r5 = (int64_t)r5 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2509 dst=r1 src=r10 offset=0 imm=0
#line 261 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2510 dst=r1 src=r0 offset=0 imm=-112
#line 261 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=2511 dst=r2 src=r0 offset=0 imm=55
#line 261 "sample/undocked/map.c"
    r2 = IMMEDIATE(55);
    // EBPF_OP_MOV64_IMM pc=2512 dst=r4 src=r0 offset=0 imm=-29
#line 261 "sample/undocked/map.c"
    r4 = IMMEDIATE(-29);
    // EBPF_OP_JA pc=2513 dst=r0 src=r0 offset=-184 imm=0
#line 261 "sample/undocked/map.c"
    goto label_148;
label_159:
    // EBPF_OP_STXW pc=2514 dst=r10 src=r6 offset=-4 imm=0
#line 262 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=2515 dst=r2 src=r10 offset=0 imm=0
#line 262 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2516 dst=r2 src=r0 offset=0 imm=-4
#line 262 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2517 dst=r1 src=r1 offset=0 imm=8
#line 262 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_MOV64_IMM pc=2519 dst=r3 src=r0 offset=0 imm=2
#line 262 "sample/undocked/map.c"
    r3 = IMMEDIATE(2);
    // EBPF_OP_CALL pc=2520 dst=r0 src=r0 offset=0 imm=16
#line 262 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[9].address(r1, r2, r3, r4, r5, context);
#line 262 "sample/undocked/map.c"
    if ((runtime_context->helper_data[9].tail_call) && (r0 == 0)) {
#line 262 "sample/undocked/map.c"
        return 0;
#line 262 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=2521 dst=r7 src=r0 offset=0 imm=0
#line 262 "sample/undocked/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2522 dst=r5 src=r7 offset=0 imm=0
#line 262 "sample/undocked/map.c"
    r5 = r7;
    // EBPF_OP_LSH64_IMM pc=2523 dst=r5 src=r0 offset=0 imm=32
#line 262 "sample/undocked/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2524 dst=r1 src=r5 offset=0 imm=0
#line 262 "sample/undocked/map.c"
    r1 = r5;
    // EBPF_OP_RSH64_IMM pc=2525 dst=r1 src=r0 offset=0 imm=32
#line 262 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2526 dst=r1 src=r0 offset=25 imm=0
#line 262 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 262 "sample/undocked/map.c"
        goto label_160;
#line 262 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_IMM pc=2527 dst=r1 src=r0 offset=0 imm=25637
#line 262 "sample/undocked/map.c"
    r1 = IMMEDIATE(25637);
    // EBPF_OP_STXH pc=2528 dst=r10 src=r1 offset=-60 imm=0
#line 262 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-60)) = (uint16_t)r1;
    // EBPF_OP_MOV64_IMM pc=2529 dst=r1 src=r0 offset=0 imm=543450478
#line 262 "sample/undocked/map.c"
    r1 = IMMEDIATE(543450478);
    // EBPF_OP_STXW pc=2530 dst=r10 src=r1 offset=-64 imm=0
#line 262 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint32_t)r1;
    // EBPF_OP_LDDW pc=2531 dst=r1 src=r0 offset=0 imm=1914725413
#line 262 "sample/undocked/map.c"
    r1 = (uint64_t)8247626271654175781;
    // EBPF_OP_STXDW pc=2533 dst=r10 src=r1 offset=-72 imm=0
#line 262 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2534 dst=r1 src=r0 offset=0 imm=1667592312
#line 262 "sample/undocked/map.c"
    r1 = (uint64_t)2334102057442963576;
    // EBPF_OP_STXDW pc=2536 dst=r10 src=r1 offset=-80 imm=0
#line 262 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2537 dst=r1 src=r0 offset=0 imm=543649385
#line 262 "sample/undocked/map.c"
    r1 = (uint64_t)7286934307705679465;
    // EBPF_OP_STXDW pc=2539 dst=r10 src=r1 offset=-88 imm=0
#line 262 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2540 dst=r1 src=r0 offset=0 imm=1852383341
#line 262 "sample/undocked/map.c"
    r1 = (uint64_t)8390880602192683117;
    // EBPF_OP_STXDW pc=2542 dst=r10 src=r1 offset=-96 imm=0
#line 262 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2543 dst=r1 src=r0 offset=0 imm=1752397168
#line 262 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755764168048;
    // EBPF_OP_STXDW pc=2545 dst=r10 src=r1 offset=-104 imm=0
#line 262 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2546 dst=r1 src=r0 offset=0 imm=1600548962
#line 262 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2548 dst=r10 src=r1 offset=-112 imm=0
#line 262 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_IMM pc=2549 dst=r1 src=r0 offset=0 imm=0
#line 262 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=2550 dst=r10 src=r1 offset=-58 imm=0
#line 262 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-58)) = (uint8_t)r1;
    // EBPF_OP_JA pc=2551 dst=r0 src=r0 offset=-228 imm=0
#line 262 "sample/undocked/map.c"
    goto label_147;
label_160:
    // EBPF_OP_MOV64_IMM pc=2552 dst=r1 src=r0 offset=0 imm=0
#line 262 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2553 dst=r10 src=r1 offset=-4 imm=0
#line 264 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=2554 dst=r2 src=r10 offset=0 imm=0
#line 264 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2555 dst=r2 src=r0 offset=0 imm=-4
#line 264 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2556 dst=r1 src=r1 offset=0 imm=8
#line 264 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_CALL pc=2558 dst=r0 src=r0 offset=0 imm=18
#line 264 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[6].address(r1, r2, r3, r4, r5, context);
#line 264 "sample/undocked/map.c"
    if ((runtime_context->helper_data[6].tail_call) && (r0 == 0)) {
#line 264 "sample/undocked/map.c"
        return 0;
#line 264 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=2559 dst=r7 src=r0 offset=0 imm=0
#line 264 "sample/undocked/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2560 dst=r4 src=r7 offset=0 imm=0
#line 264 "sample/undocked/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=2561 dst=r4 src=r0 offset=0 imm=32
#line 264 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2562 dst=r1 src=r4 offset=0 imm=0
#line 264 "sample/undocked/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=2563 dst=r1 src=r0 offset=0 imm=32
#line 264 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2564 dst=r1 src=r0 offset=25 imm=0
#line 264 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 264 "sample/undocked/map.c"
        goto label_161;
#line 264 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_IMM pc=2565 dst=r1 src=r0 offset=0 imm=100
#line 264 "sample/undocked/map.c"
    r1 = IMMEDIATE(100);
    // EBPF_OP_STXH pc=2566 dst=r10 src=r1 offset=-64 imm=0
#line 264 "sample/undocked/map.c"
    *(uint16_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint16_t)r1;
    // EBPF_OP_LDDW pc=2567 dst=r1 src=r0 offset=0 imm=1852994932
#line 264 "sample/undocked/map.c"
    r1 = (uint64_t)2675248565465544052;
    // EBPF_OP_STXDW pc=2569 dst=r10 src=r1 offset=-72 imm=0
#line 264 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2570 dst=r1 src=r0 offset=0 imm=622883948
#line 264 "sample/undocked/map.c"
    r1 = (uint64_t)7309940759667438700;
    // EBPF_OP_STXDW pc=2572 dst=r10 src=r1 offset=-80 imm=0
#line 264 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2573 dst=r1 src=r0 offset=0 imm=543649385
#line 264 "sample/undocked/map.c"
    r1 = (uint64_t)8463219665603620457;
    // EBPF_OP_STXDW pc=2575 dst=r10 src=r1 offset=-88 imm=0
#line 264 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2576 dst=r1 src=r0 offset=0 imm=2019893357
#line 264 "sample/undocked/map.c"
    r1 = (uint64_t)8386658464824631405;
    // EBPF_OP_STXDW pc=2578 dst=r10 src=r1 offset=-96 imm=0
#line 264 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2579 dst=r1 src=r0 offset=0 imm=1801807216
#line 264 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=2581 dst=r10 src=r1 offset=-104 imm=0
#line 264 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2582 dst=r1 src=r0 offset=0 imm=1600548962
#line 264 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2584 dst=r10 src=r1 offset=-112 imm=0
#line 264 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_ARSH64_IMM pc=2585 dst=r4 src=r0 offset=0 imm=32
#line 264 "sample/undocked/map.c"
    r4 = (int64_t)r4 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2586 dst=r1 src=r10 offset=0 imm=0
#line 264 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2587 dst=r1 src=r0 offset=0 imm=-112
#line 264 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=2588 dst=r2 src=r0 offset=0 imm=50
#line 264 "sample/undocked/map.c"
    r2 = IMMEDIATE(50);
    // EBPF_OP_JA pc=2589 dst=r0 src=r0 offset=60 imm=0
#line 264 "sample/undocked/map.c"
    goto label_164;
label_161:
    // EBPF_OP_LDXW pc=2590 dst=r3 src=r10 offset=-4 imm=0
#line 264 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=2591 dst=r3 src=r0 offset=22 imm=10
#line 264 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(10)) {
#line 264 "sample/undocked/map.c"
        goto label_162;
#line 264 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_IMM pc=2592 dst=r1 src=r0 offset=0 imm=0
#line 264 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXB pc=2593 dst=r10 src=r1 offset=-72 imm=0
#line 264 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint8_t)r1;
    // EBPF_OP_LDDW pc=2594 dst=r1 src=r0 offset=0 imm=1852404835
#line 264 "sample/undocked/map.c"
    r1 = (uint64_t)7216209606537213027;
    // EBPF_OP_STXDW pc=2596 dst=r10 src=r1 offset=-80 imm=0
#line 264 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2597 dst=r1 src=r0 offset=0 imm=543434016
#line 264 "sample/undocked/map.c"
    r1 = (uint64_t)7309474570952779040;
    // EBPF_OP_STXDW pc=2599 dst=r10 src=r1 offset=-88 imm=0
#line 264 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2600 dst=r1 src=r0 offset=0 imm=1701978221
#line 264 "sample/undocked/map.c"
    r1 = (uint64_t)7958552634295722093;
    // EBPF_OP_STXDW pc=2602 dst=r10 src=r1 offset=-96 imm=0
#line 264 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2603 dst=r1 src=r0 offset=0 imm=1801807216
#line 264 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755813578096;
    // EBPF_OP_STXDW pc=2605 dst=r10 src=r1 offset=-104 imm=0
#line 264 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2606 dst=r1 src=r0 offset=0 imm=1600548962
#line 264 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2608 dst=r10 src=r1 offset=-112 imm=0
#line 264 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=2609 dst=r1 src=r10 offset=0 imm=0
#line 264 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2610 dst=r1 src=r0 offset=0 imm=-112
#line 264 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=2611 dst=r2 src=r0 offset=0 imm=41
#line 264 "sample/undocked/map.c"
    r2 = IMMEDIATE(41);
    // EBPF_OP_MOV64_IMM pc=2612 dst=r4 src=r0 offset=0 imm=10
#line 264 "sample/undocked/map.c"
    r4 = IMMEDIATE(10);
    // EBPF_OP_JA pc=2613 dst=r0 src=r0 offset=-415 imm=0
#line 264 "sample/undocked/map.c"
    goto label_139;
label_162:
    // EBPF_OP_MOV64_IMM pc=2614 dst=r6 src=r0 offset=0 imm=0
#line 264 "sample/undocked/map.c"
    r6 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2615 dst=r10 src=r6 offset=-4 imm=0
#line 272 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=2616 dst=r2 src=r10 offset=0 imm=0
#line 272 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2617 dst=r2 src=r0 offset=0 imm=-4
#line 272 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2618 dst=r1 src=r1 offset=0 imm=8
#line 272 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_CALL pc=2620 dst=r0 src=r0 offset=0 imm=17
#line 272 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[8].address(r1, r2, r3, r4, r5, context);
#line 272 "sample/undocked/map.c"
    if ((runtime_context->helper_data[8].tail_call) && (r0 == 0)) {
#line 272 "sample/undocked/map.c"
        return 0;
#line 272 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=2621 dst=r7 src=r0 offset=0 imm=0
#line 272 "sample/undocked/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2622 dst=r4 src=r7 offset=0 imm=0
#line 272 "sample/undocked/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=2623 dst=r4 src=r0 offset=0 imm=32
#line 272 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2624 dst=r1 src=r4 offset=0 imm=0
#line 272 "sample/undocked/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=2625 dst=r1 src=r0 offset=0 imm=32
#line 272 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2626 dst=r1 src=r0 offset=26 imm=0
#line 272 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 272 "sample/undocked/map.c"
        goto label_165;
#line 272 "sample/undocked/map.c"
    }
label_163:
    // EBPF_OP_LDDW pc=2627 dst=r1 src=r0 offset=0 imm=1701737077
#line 272 "sample/undocked/map.c"
    r1 = (uint64_t)7216209593501643381;
    // EBPF_OP_STXDW pc=2629 dst=r10 src=r1 offset=-72 imm=0
#line 272 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-72)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2630 dst=r1 src=r0 offset=0 imm=1680154740
#line 272 "sample/undocked/map.c"
    r1 = (uint64_t)8387235364492091508;
    // EBPF_OP_STXDW pc=2632 dst=r10 src=r1 offset=-80 imm=0
#line 272 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2633 dst=r1 src=r0 offset=0 imm=1914726254
#line 272 "sample/undocked/map.c"
    r1 = (uint64_t)7815279607914981230;
    // EBPF_OP_STXDW pc=2635 dst=r10 src=r1 offset=-88 imm=0
#line 272 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2636 dst=r1 src=r0 offset=0 imm=1886938400
#line 272 "sample/undocked/map.c"
    r1 = (uint64_t)7598807758610654496;
    // EBPF_OP_STXDW pc=2638 dst=r10 src=r1 offset=-96 imm=0
#line 272 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2639 dst=r1 src=r0 offset=0 imm=1601204080
#line 272 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=2641 dst=r10 src=r1 offset=-104 imm=0
#line 272 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2642 dst=r1 src=r0 offset=0 imm=1600548962
#line 272 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2644 dst=r10 src=r1 offset=-112 imm=0
#line 272 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_STXB pc=2645 dst=r10 src=r6 offset=-64 imm=0
#line 272 "sample/undocked/map.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-64)) = (uint8_t)r6;
    // EBPF_OP_ARSH64_IMM pc=2646 dst=r4 src=r0 offset=0 imm=32
#line 272 "sample/undocked/map.c"
    r4 = (int64_t)r4 >> (uint32_t)(IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2647 dst=r1 src=r10 offset=0 imm=0
#line 272 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2648 dst=r1 src=r0 offset=0 imm=-112
#line 272 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=2649 dst=r2 src=r0 offset=0 imm=49
#line 272 "sample/undocked/map.c"
    r2 = IMMEDIATE(49);
label_164:
    // EBPF_OP_MOV64_IMM pc=2650 dst=r3 src=r0 offset=0 imm=0
#line 272 "sample/undocked/map.c"
    r3 = IMMEDIATE(0);
    // EBPF_OP_CALL pc=2651 dst=r0 src=r0 offset=0 imm=14
#line 272 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[7].address(r1, r2, r3, r4, r5, context);
#line 272 "sample/undocked/map.c"
    if ((runtime_context->helper_data[7].tail_call) && (r0 == 0)) {
#line 272 "sample/undocked/map.c"
        return 0;
#line 272 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=2652 dst=r0 src=r0 offset=-451 imm=0
#line 272 "sample/undocked/map.c"
    goto label_140;
label_165:
    // EBPF_OP_LDXW pc=2653 dst=r3 src=r10 offset=-4 imm=0
#line 272 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=2654 dst=r3 src=r0 offset=20 imm=10
#line 272 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(10)) {
#line 272 "sample/undocked/map.c"
        goto label_166;
#line 272 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=2655 dst=r1 src=r0 offset=0 imm=1735289204
#line 272 "sample/undocked/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=2657 dst=r10 src=r1 offset=-80 imm=0
#line 272 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2658 dst=r1 src=r0 offset=0 imm=1696621605
#line 272 "sample/undocked/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=2660 dst=r10 src=r1 offset=-88 imm=0
#line 272 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2661 dst=r1 src=r0 offset=0 imm=1952805408
#line 272 "sample/undocked/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=2663 dst=r10 src=r1 offset=-96 imm=0
#line 272 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2664 dst=r1 src=r0 offset=0 imm=1601204080
#line 272 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=2666 dst=r10 src=r1 offset=-104 imm=0
#line 272 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2667 dst=r1 src=r0 offset=0 imm=1600548962
#line 272 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2669 dst=r10 src=r1 offset=-112 imm=0
#line 272 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=2670 dst=r1 src=r10 offset=0 imm=0
#line 272 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2671 dst=r1 src=r0 offset=0 imm=-112
#line 272 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=2672 dst=r2 src=r0 offset=0 imm=40
#line 272 "sample/undocked/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_MOV64_IMM pc=2673 dst=r4 src=r0 offset=0 imm=10
#line 272 "sample/undocked/map.c"
    r4 = IMMEDIATE(10);
    // EBPF_OP_JA pc=2674 dst=r0 src=r0 offset=-476 imm=0
#line 272 "sample/undocked/map.c"
    goto label_139;
label_166:
    // EBPF_OP_STXW pc=2675 dst=r10 src=r6 offset=-4 imm=0
#line 273 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=2676 dst=r2 src=r10 offset=0 imm=0
#line 273 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2677 dst=r2 src=r0 offset=0 imm=-4
#line 273 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2678 dst=r1 src=r1 offset=0 imm=8
#line 273 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_CALL pc=2680 dst=r0 src=r0 offset=0 imm=17
#line 273 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[8].address(r1, r2, r3, r4, r5, context);
#line 273 "sample/undocked/map.c"
    if ((runtime_context->helper_data[8].tail_call) && (r0 == 0)) {
#line 273 "sample/undocked/map.c"
        return 0;
#line 273 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=2681 dst=r7 src=r0 offset=0 imm=0
#line 273 "sample/undocked/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2682 dst=r4 src=r7 offset=0 imm=0
#line 273 "sample/undocked/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=2683 dst=r4 src=r0 offset=0 imm=32
#line 273 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2684 dst=r1 src=r4 offset=0 imm=0
#line 273 "sample/undocked/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=2685 dst=r1 src=r0 offset=0 imm=32
#line 273 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2686 dst=r1 src=r0 offset=1 imm=0
#line 273 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 273 "sample/undocked/map.c"
        goto label_167;
#line 273 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=2687 dst=r0 src=r0 offset=-61 imm=0
#line 273 "sample/undocked/map.c"
    goto label_163;
label_167:
    // EBPF_OP_LDXW pc=2688 dst=r3 src=r10 offset=-4 imm=0
#line 273 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=2689 dst=r3 src=r0 offset=20 imm=9
#line 273 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(9)) {
#line 273 "sample/undocked/map.c"
        goto label_168;
#line 273 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=2690 dst=r1 src=r0 offset=0 imm=1735289204
#line 273 "sample/undocked/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=2692 dst=r10 src=r1 offset=-80 imm=0
#line 273 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2693 dst=r1 src=r0 offset=0 imm=1696621605
#line 273 "sample/undocked/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=2695 dst=r10 src=r1 offset=-88 imm=0
#line 273 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2696 dst=r1 src=r0 offset=0 imm=1952805408
#line 273 "sample/undocked/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=2698 dst=r10 src=r1 offset=-96 imm=0
#line 273 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2699 dst=r1 src=r0 offset=0 imm=1601204080
#line 273 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=2701 dst=r10 src=r1 offset=-104 imm=0
#line 273 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2702 dst=r1 src=r0 offset=0 imm=1600548962
#line 273 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2704 dst=r10 src=r1 offset=-112 imm=0
#line 273 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=2705 dst=r1 src=r10 offset=0 imm=0
#line 273 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2706 dst=r1 src=r0 offset=0 imm=-112
#line 273 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=2707 dst=r2 src=r0 offset=0 imm=40
#line 273 "sample/undocked/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_MOV64_IMM pc=2708 dst=r4 src=r0 offset=0 imm=9
#line 273 "sample/undocked/map.c"
    r4 = IMMEDIATE(9);
    // EBPF_OP_JA pc=2709 dst=r0 src=r0 offset=-511 imm=0
#line 273 "sample/undocked/map.c"
    goto label_139;
label_168:
    // EBPF_OP_STXW pc=2710 dst=r10 src=r6 offset=-4 imm=0
#line 274 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=2711 dst=r2 src=r10 offset=0 imm=0
#line 274 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2712 dst=r2 src=r0 offset=0 imm=-4
#line 274 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2713 dst=r1 src=r1 offset=0 imm=8
#line 274 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_CALL pc=2715 dst=r0 src=r0 offset=0 imm=17
#line 274 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[8].address(r1, r2, r3, r4, r5, context);
#line 274 "sample/undocked/map.c"
    if ((runtime_context->helper_data[8].tail_call) && (r0 == 0)) {
#line 274 "sample/undocked/map.c"
        return 0;
#line 274 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=2716 dst=r7 src=r0 offset=0 imm=0
#line 274 "sample/undocked/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2717 dst=r4 src=r7 offset=0 imm=0
#line 274 "sample/undocked/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=2718 dst=r4 src=r0 offset=0 imm=32
#line 274 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2719 dst=r1 src=r4 offset=0 imm=0
#line 274 "sample/undocked/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=2720 dst=r1 src=r0 offset=0 imm=32
#line 274 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2721 dst=r1 src=r0 offset=1 imm=0
#line 274 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 274 "sample/undocked/map.c"
        goto label_169;
#line 274 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=2722 dst=r0 src=r0 offset=-96 imm=0
#line 274 "sample/undocked/map.c"
    goto label_163;
label_169:
    // EBPF_OP_LDXW pc=2723 dst=r3 src=r10 offset=-4 imm=0
#line 274 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=2724 dst=r3 src=r0 offset=20 imm=8
#line 274 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(8)) {
#line 274 "sample/undocked/map.c"
        goto label_170;
#line 274 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=2725 dst=r1 src=r0 offset=0 imm=1735289204
#line 274 "sample/undocked/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=2727 dst=r10 src=r1 offset=-80 imm=0
#line 274 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2728 dst=r1 src=r0 offset=0 imm=1696621605
#line 274 "sample/undocked/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=2730 dst=r10 src=r1 offset=-88 imm=0
#line 274 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2731 dst=r1 src=r0 offset=0 imm=1952805408
#line 274 "sample/undocked/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=2733 dst=r10 src=r1 offset=-96 imm=0
#line 274 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2734 dst=r1 src=r0 offset=0 imm=1601204080
#line 274 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=2736 dst=r10 src=r1 offset=-104 imm=0
#line 274 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2737 dst=r1 src=r0 offset=0 imm=1600548962
#line 274 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2739 dst=r10 src=r1 offset=-112 imm=0
#line 274 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=2740 dst=r1 src=r10 offset=0 imm=0
#line 274 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2741 dst=r1 src=r0 offset=0 imm=-112
#line 274 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=2742 dst=r2 src=r0 offset=0 imm=40
#line 274 "sample/undocked/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_MOV64_IMM pc=2743 dst=r4 src=r0 offset=0 imm=8
#line 274 "sample/undocked/map.c"
    r4 = IMMEDIATE(8);
    // EBPF_OP_JA pc=2744 dst=r0 src=r0 offset=-546 imm=0
#line 274 "sample/undocked/map.c"
    goto label_139;
label_170:
    // EBPF_OP_STXW pc=2745 dst=r10 src=r6 offset=-4 imm=0
#line 275 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=2746 dst=r2 src=r10 offset=0 imm=0
#line 275 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2747 dst=r2 src=r0 offset=0 imm=-4
#line 275 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2748 dst=r1 src=r1 offset=0 imm=8
#line 275 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_CALL pc=2750 dst=r0 src=r0 offset=0 imm=17
#line 275 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[8].address(r1, r2, r3, r4, r5, context);
#line 275 "sample/undocked/map.c"
    if ((runtime_context->helper_data[8].tail_call) && (r0 == 0)) {
#line 275 "sample/undocked/map.c"
        return 0;
#line 275 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=2751 dst=r7 src=r0 offset=0 imm=0
#line 275 "sample/undocked/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2752 dst=r4 src=r7 offset=0 imm=0
#line 275 "sample/undocked/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=2753 dst=r4 src=r0 offset=0 imm=32
#line 275 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2754 dst=r1 src=r4 offset=0 imm=0
#line 275 "sample/undocked/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=2755 dst=r1 src=r0 offset=0 imm=32
#line 275 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2756 dst=r1 src=r0 offset=1 imm=0
#line 275 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 275 "sample/undocked/map.c"
        goto label_171;
#line 275 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=2757 dst=r0 src=r0 offset=-131 imm=0
#line 275 "sample/undocked/map.c"
    goto label_163;
label_171:
    // EBPF_OP_LDXW pc=2758 dst=r3 src=r10 offset=-4 imm=0
#line 275 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=2759 dst=r3 src=r0 offset=20 imm=7
#line 275 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(7)) {
#line 275 "sample/undocked/map.c"
        goto label_172;
#line 275 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=2760 dst=r1 src=r0 offset=0 imm=1735289204
#line 275 "sample/undocked/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=2762 dst=r10 src=r1 offset=-80 imm=0
#line 275 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2763 dst=r1 src=r0 offset=0 imm=1696621605
#line 275 "sample/undocked/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=2765 dst=r10 src=r1 offset=-88 imm=0
#line 275 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2766 dst=r1 src=r0 offset=0 imm=1952805408
#line 275 "sample/undocked/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=2768 dst=r10 src=r1 offset=-96 imm=0
#line 275 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2769 dst=r1 src=r0 offset=0 imm=1601204080
#line 275 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=2771 dst=r10 src=r1 offset=-104 imm=0
#line 275 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2772 dst=r1 src=r0 offset=0 imm=1600548962
#line 275 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2774 dst=r10 src=r1 offset=-112 imm=0
#line 275 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=2775 dst=r1 src=r10 offset=0 imm=0
#line 275 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2776 dst=r1 src=r0 offset=0 imm=-112
#line 275 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=2777 dst=r2 src=r0 offset=0 imm=40
#line 275 "sample/undocked/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_MOV64_IMM pc=2778 dst=r4 src=r0 offset=0 imm=7
#line 275 "sample/undocked/map.c"
    r4 = IMMEDIATE(7);
    // EBPF_OP_JA pc=2779 dst=r0 src=r0 offset=-581 imm=0
#line 275 "sample/undocked/map.c"
    goto label_139;
label_172:
    // EBPF_OP_STXW pc=2780 dst=r10 src=r6 offset=-4 imm=0
#line 276 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=2781 dst=r2 src=r10 offset=0 imm=0
#line 276 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2782 dst=r2 src=r0 offset=0 imm=-4
#line 276 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2783 dst=r1 src=r1 offset=0 imm=8
#line 276 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_CALL pc=2785 dst=r0 src=r0 offset=0 imm=17
#line 276 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[8].address(r1, r2, r3, r4, r5, context);
#line 276 "sample/undocked/map.c"
    if ((runtime_context->helper_data[8].tail_call) && (r0 == 0)) {
#line 276 "sample/undocked/map.c"
        return 0;
#line 276 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=2786 dst=r7 src=r0 offset=0 imm=0
#line 276 "sample/undocked/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2787 dst=r4 src=r7 offset=0 imm=0
#line 276 "sample/undocked/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=2788 dst=r4 src=r0 offset=0 imm=32
#line 276 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2789 dst=r1 src=r4 offset=0 imm=0
#line 276 "sample/undocked/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=2790 dst=r1 src=r0 offset=0 imm=32
#line 276 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2791 dst=r1 src=r0 offset=1 imm=0
#line 276 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 276 "sample/undocked/map.c"
        goto label_173;
#line 276 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=2792 dst=r0 src=r0 offset=-166 imm=0
#line 276 "sample/undocked/map.c"
    goto label_163;
label_173:
    // EBPF_OP_LDXW pc=2793 dst=r3 src=r10 offset=-4 imm=0
#line 276 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=2794 dst=r3 src=r0 offset=20 imm=6
#line 276 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(6)) {
#line 276 "sample/undocked/map.c"
        goto label_174;
#line 276 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=2795 dst=r1 src=r0 offset=0 imm=1735289204
#line 276 "sample/undocked/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=2797 dst=r10 src=r1 offset=-80 imm=0
#line 276 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2798 dst=r1 src=r0 offset=0 imm=1696621605
#line 276 "sample/undocked/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=2800 dst=r10 src=r1 offset=-88 imm=0
#line 276 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2801 dst=r1 src=r0 offset=0 imm=1952805408
#line 276 "sample/undocked/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=2803 dst=r10 src=r1 offset=-96 imm=0
#line 276 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2804 dst=r1 src=r0 offset=0 imm=1601204080
#line 276 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=2806 dst=r10 src=r1 offset=-104 imm=0
#line 276 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2807 dst=r1 src=r0 offset=0 imm=1600548962
#line 276 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2809 dst=r10 src=r1 offset=-112 imm=0
#line 276 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=2810 dst=r1 src=r10 offset=0 imm=0
#line 276 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2811 dst=r1 src=r0 offset=0 imm=-112
#line 276 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=2812 dst=r2 src=r0 offset=0 imm=40
#line 276 "sample/undocked/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_MOV64_IMM pc=2813 dst=r4 src=r0 offset=0 imm=6
#line 276 "sample/undocked/map.c"
    r4 = IMMEDIATE(6);
    // EBPF_OP_JA pc=2814 dst=r0 src=r0 offset=-616 imm=0
#line 276 "sample/undocked/map.c"
    goto label_139;
label_174:
    // EBPF_OP_STXW pc=2815 dst=r10 src=r6 offset=-4 imm=0
#line 277 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=2816 dst=r2 src=r10 offset=0 imm=0
#line 277 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2817 dst=r2 src=r0 offset=0 imm=-4
#line 277 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2818 dst=r1 src=r1 offset=0 imm=8
#line 277 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_CALL pc=2820 dst=r0 src=r0 offset=0 imm=17
#line 277 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[8].address(r1, r2, r3, r4, r5, context);
#line 277 "sample/undocked/map.c"
    if ((runtime_context->helper_data[8].tail_call) && (r0 == 0)) {
#line 277 "sample/undocked/map.c"
        return 0;
#line 277 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=2821 dst=r7 src=r0 offset=0 imm=0
#line 277 "sample/undocked/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2822 dst=r4 src=r7 offset=0 imm=0
#line 277 "sample/undocked/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=2823 dst=r4 src=r0 offset=0 imm=32
#line 277 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2824 dst=r1 src=r4 offset=0 imm=0
#line 277 "sample/undocked/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=2825 dst=r1 src=r0 offset=0 imm=32
#line 277 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2826 dst=r1 src=r0 offset=1 imm=0
#line 277 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 277 "sample/undocked/map.c"
        goto label_175;
#line 277 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=2827 dst=r0 src=r0 offset=-201 imm=0
#line 277 "sample/undocked/map.c"
    goto label_163;
label_175:
    // EBPF_OP_LDXW pc=2828 dst=r3 src=r10 offset=-4 imm=0
#line 277 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=2829 dst=r3 src=r0 offset=20 imm=5
#line 277 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(5)) {
#line 277 "sample/undocked/map.c"
        goto label_176;
#line 277 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=2830 dst=r1 src=r0 offset=0 imm=1735289204
#line 277 "sample/undocked/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=2832 dst=r10 src=r1 offset=-80 imm=0
#line 277 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2833 dst=r1 src=r0 offset=0 imm=1696621605
#line 277 "sample/undocked/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=2835 dst=r10 src=r1 offset=-88 imm=0
#line 277 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2836 dst=r1 src=r0 offset=0 imm=1952805408
#line 277 "sample/undocked/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=2838 dst=r10 src=r1 offset=-96 imm=0
#line 277 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2839 dst=r1 src=r0 offset=0 imm=1601204080
#line 277 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=2841 dst=r10 src=r1 offset=-104 imm=0
#line 277 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2842 dst=r1 src=r0 offset=0 imm=1600548962
#line 277 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2844 dst=r10 src=r1 offset=-112 imm=0
#line 277 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=2845 dst=r1 src=r10 offset=0 imm=0
#line 277 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2846 dst=r1 src=r0 offset=0 imm=-112
#line 277 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=2847 dst=r2 src=r0 offset=0 imm=40
#line 277 "sample/undocked/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_MOV64_IMM pc=2848 dst=r4 src=r0 offset=0 imm=5
#line 277 "sample/undocked/map.c"
    r4 = IMMEDIATE(5);
    // EBPF_OP_JA pc=2849 dst=r0 src=r0 offset=-651 imm=0
#line 277 "sample/undocked/map.c"
    goto label_139;
label_176:
    // EBPF_OP_STXW pc=2850 dst=r10 src=r6 offset=-4 imm=0
#line 278 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=2851 dst=r2 src=r10 offset=0 imm=0
#line 278 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2852 dst=r2 src=r0 offset=0 imm=-4
#line 278 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2853 dst=r1 src=r1 offset=0 imm=8
#line 278 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_CALL pc=2855 dst=r0 src=r0 offset=0 imm=17
#line 278 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[8].address(r1, r2, r3, r4, r5, context);
#line 278 "sample/undocked/map.c"
    if ((runtime_context->helper_data[8].tail_call) && (r0 == 0)) {
#line 278 "sample/undocked/map.c"
        return 0;
#line 278 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=2856 dst=r7 src=r0 offset=0 imm=0
#line 278 "sample/undocked/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2857 dst=r4 src=r7 offset=0 imm=0
#line 278 "sample/undocked/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=2858 dst=r4 src=r0 offset=0 imm=32
#line 278 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2859 dst=r1 src=r4 offset=0 imm=0
#line 278 "sample/undocked/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=2860 dst=r1 src=r0 offset=0 imm=32
#line 278 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2861 dst=r1 src=r0 offset=1 imm=0
#line 278 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 278 "sample/undocked/map.c"
        goto label_177;
#line 278 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=2862 dst=r0 src=r0 offset=-236 imm=0
#line 278 "sample/undocked/map.c"
    goto label_163;
label_177:
    // EBPF_OP_LDXW pc=2863 dst=r3 src=r10 offset=-4 imm=0
#line 278 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=2864 dst=r3 src=r0 offset=20 imm=4
#line 278 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(4)) {
#line 278 "sample/undocked/map.c"
        goto label_178;
#line 278 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=2865 dst=r1 src=r0 offset=0 imm=1735289204
#line 278 "sample/undocked/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=2867 dst=r10 src=r1 offset=-80 imm=0
#line 278 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2868 dst=r1 src=r0 offset=0 imm=1696621605
#line 278 "sample/undocked/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=2870 dst=r10 src=r1 offset=-88 imm=0
#line 278 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2871 dst=r1 src=r0 offset=0 imm=1952805408
#line 278 "sample/undocked/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=2873 dst=r10 src=r1 offset=-96 imm=0
#line 278 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2874 dst=r1 src=r0 offset=0 imm=1601204080
#line 278 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=2876 dst=r10 src=r1 offset=-104 imm=0
#line 278 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2877 dst=r1 src=r0 offset=0 imm=1600548962
#line 278 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2879 dst=r10 src=r1 offset=-112 imm=0
#line 278 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=2880 dst=r1 src=r10 offset=0 imm=0
#line 278 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2881 dst=r1 src=r0 offset=0 imm=-112
#line 278 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=2882 dst=r2 src=r0 offset=0 imm=40
#line 278 "sample/undocked/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_MOV64_IMM pc=2883 dst=r4 src=r0 offset=0 imm=4
#line 278 "sample/undocked/map.c"
    r4 = IMMEDIATE(4);
    // EBPF_OP_JA pc=2884 dst=r0 src=r0 offset=-686 imm=0
#line 278 "sample/undocked/map.c"
    goto label_139;
label_178:
    // EBPF_OP_STXW pc=2885 dst=r10 src=r6 offset=-4 imm=0
#line 279 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=2886 dst=r2 src=r10 offset=0 imm=0
#line 279 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2887 dst=r2 src=r0 offset=0 imm=-4
#line 279 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2888 dst=r1 src=r1 offset=0 imm=8
#line 279 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_CALL pc=2890 dst=r0 src=r0 offset=0 imm=17
#line 279 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[8].address(r1, r2, r3, r4, r5, context);
#line 279 "sample/undocked/map.c"
    if ((runtime_context->helper_data[8].tail_call) && (r0 == 0)) {
#line 279 "sample/undocked/map.c"
        return 0;
#line 279 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=2891 dst=r7 src=r0 offset=0 imm=0
#line 279 "sample/undocked/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2892 dst=r4 src=r7 offset=0 imm=0
#line 279 "sample/undocked/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=2893 dst=r4 src=r0 offset=0 imm=32
#line 279 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2894 dst=r1 src=r4 offset=0 imm=0
#line 279 "sample/undocked/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=2895 dst=r1 src=r0 offset=0 imm=32
#line 279 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2896 dst=r1 src=r0 offset=1 imm=0
#line 279 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 279 "sample/undocked/map.c"
        goto label_179;
#line 279 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=2897 dst=r0 src=r0 offset=-271 imm=0
#line 279 "sample/undocked/map.c"
    goto label_163;
label_179:
    // EBPF_OP_LDXW pc=2898 dst=r3 src=r10 offset=-4 imm=0
#line 279 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=2899 dst=r3 src=r0 offset=20 imm=3
#line 279 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(3)) {
#line 279 "sample/undocked/map.c"
        goto label_180;
#line 279 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=2900 dst=r1 src=r0 offset=0 imm=1735289204
#line 279 "sample/undocked/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=2902 dst=r10 src=r1 offset=-80 imm=0
#line 279 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2903 dst=r1 src=r0 offset=0 imm=1696621605
#line 279 "sample/undocked/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=2905 dst=r10 src=r1 offset=-88 imm=0
#line 279 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2906 dst=r1 src=r0 offset=0 imm=1952805408
#line 279 "sample/undocked/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=2908 dst=r10 src=r1 offset=-96 imm=0
#line 279 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2909 dst=r1 src=r0 offset=0 imm=1601204080
#line 279 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=2911 dst=r10 src=r1 offset=-104 imm=0
#line 279 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2912 dst=r1 src=r0 offset=0 imm=1600548962
#line 279 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2914 dst=r10 src=r1 offset=-112 imm=0
#line 279 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=2915 dst=r1 src=r10 offset=0 imm=0
#line 279 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2916 dst=r1 src=r0 offset=0 imm=-112
#line 279 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=2917 dst=r2 src=r0 offset=0 imm=40
#line 279 "sample/undocked/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_MOV64_IMM pc=2918 dst=r4 src=r0 offset=0 imm=3
#line 279 "sample/undocked/map.c"
    r4 = IMMEDIATE(3);
    // EBPF_OP_JA pc=2919 dst=r0 src=r0 offset=-721 imm=0
#line 279 "sample/undocked/map.c"
    goto label_139;
label_180:
    // EBPF_OP_STXW pc=2920 dst=r10 src=r6 offset=-4 imm=0
#line 280 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=2921 dst=r2 src=r10 offset=0 imm=0
#line 280 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2922 dst=r2 src=r0 offset=0 imm=-4
#line 280 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2923 dst=r1 src=r1 offset=0 imm=8
#line 280 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_CALL pc=2925 dst=r0 src=r0 offset=0 imm=17
#line 280 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[8].address(r1, r2, r3, r4, r5, context);
#line 280 "sample/undocked/map.c"
    if ((runtime_context->helper_data[8].tail_call) && (r0 == 0)) {
#line 280 "sample/undocked/map.c"
        return 0;
#line 280 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=2926 dst=r7 src=r0 offset=0 imm=0
#line 280 "sample/undocked/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2927 dst=r4 src=r7 offset=0 imm=0
#line 280 "sample/undocked/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=2928 dst=r4 src=r0 offset=0 imm=32
#line 280 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2929 dst=r1 src=r4 offset=0 imm=0
#line 280 "sample/undocked/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=2930 dst=r1 src=r0 offset=0 imm=32
#line 280 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2931 dst=r1 src=r0 offset=1 imm=0
#line 280 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 280 "sample/undocked/map.c"
        goto label_181;
#line 280 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=2932 dst=r0 src=r0 offset=-306 imm=0
#line 280 "sample/undocked/map.c"
    goto label_163;
label_181:
    // EBPF_OP_LDXW pc=2933 dst=r3 src=r10 offset=-4 imm=0
#line 280 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=2934 dst=r3 src=r0 offset=20 imm=2
#line 280 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(2)) {
#line 280 "sample/undocked/map.c"
        goto label_182;
#line 280 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=2935 dst=r1 src=r0 offset=0 imm=1735289204
#line 280 "sample/undocked/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=2937 dst=r10 src=r1 offset=-80 imm=0
#line 280 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2938 dst=r1 src=r0 offset=0 imm=1696621605
#line 280 "sample/undocked/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=2940 dst=r10 src=r1 offset=-88 imm=0
#line 280 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2941 dst=r1 src=r0 offset=0 imm=1952805408
#line 280 "sample/undocked/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=2943 dst=r10 src=r1 offset=-96 imm=0
#line 280 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2944 dst=r1 src=r0 offset=0 imm=1601204080
#line 280 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=2946 dst=r10 src=r1 offset=-104 imm=0
#line 280 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2947 dst=r1 src=r0 offset=0 imm=1600548962
#line 280 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2949 dst=r10 src=r1 offset=-112 imm=0
#line 280 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=2950 dst=r1 src=r10 offset=0 imm=0
#line 280 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2951 dst=r1 src=r0 offset=0 imm=-112
#line 280 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=2952 dst=r2 src=r0 offset=0 imm=40
#line 280 "sample/undocked/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_MOV64_IMM pc=2953 dst=r4 src=r0 offset=0 imm=2
#line 280 "sample/undocked/map.c"
    r4 = IMMEDIATE(2);
    // EBPF_OP_JA pc=2954 dst=r0 src=r0 offset=-756 imm=0
#line 280 "sample/undocked/map.c"
    goto label_139;
label_182:
    // EBPF_OP_STXW pc=2955 dst=r10 src=r6 offset=-4 imm=0
#line 281 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=2956 dst=r2 src=r10 offset=0 imm=0
#line 281 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2957 dst=r2 src=r0 offset=0 imm=-4
#line 281 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2958 dst=r1 src=r1 offset=0 imm=8
#line 281 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_CALL pc=2960 dst=r0 src=r0 offset=0 imm=17
#line 281 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[8].address(r1, r2, r3, r4, r5, context);
#line 281 "sample/undocked/map.c"
    if ((runtime_context->helper_data[8].tail_call) && (r0 == 0)) {
#line 281 "sample/undocked/map.c"
        return 0;
#line 281 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=2961 dst=r7 src=r0 offset=0 imm=0
#line 281 "sample/undocked/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2962 dst=r4 src=r7 offset=0 imm=0
#line 281 "sample/undocked/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=2963 dst=r4 src=r0 offset=0 imm=32
#line 281 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=2964 dst=r1 src=r4 offset=0 imm=0
#line 281 "sample/undocked/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=2965 dst=r1 src=r0 offset=0 imm=32
#line 281 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JEQ_IMM pc=2966 dst=r1 src=r0 offset=1 imm=0
#line 281 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 281 "sample/undocked/map.c"
        goto label_183;
#line 281 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=2967 dst=r0 src=r0 offset=-341 imm=0
#line 281 "sample/undocked/map.c"
    goto label_163;
label_183:
    // EBPF_OP_LDXW pc=2968 dst=r3 src=r10 offset=-4 imm=0
#line 281 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=2969 dst=r3 src=r0 offset=20 imm=1
#line 281 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(1)) {
#line 281 "sample/undocked/map.c"
        goto label_184;
#line 281 "sample/undocked/map.c"
    }
    // EBPF_OP_LDDW pc=2970 dst=r1 src=r0 offset=0 imm=1735289204
#line 281 "sample/undocked/map.c"
    r1 = (uint64_t)28188318775535988;
    // EBPF_OP_STXDW pc=2972 dst=r10 src=r1 offset=-80 imm=0
#line 281 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-80)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2973 dst=r1 src=r0 offset=0 imm=1696621605
#line 281 "sample/undocked/map.c"
    r1 = (uint64_t)7162254444797649957;
    // EBPF_OP_STXDW pc=2975 dst=r10 src=r1 offset=-88 imm=0
#line 281 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-88)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2976 dst=r1 src=r0 offset=0 imm=1952805408
#line 281 "sample/undocked/map.c"
    r1 = (uint64_t)2336931105441411616;
    // EBPF_OP_STXDW pc=2978 dst=r10 src=r1 offset=-96 imm=0
#line 281 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-96)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2979 dst=r1 src=r0 offset=0 imm=1601204080
#line 281 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
    // EBPF_OP_STXDW pc=2981 dst=r10 src=r1 offset=-104 imm=0
#line 281 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-104)) = (uint64_t)r1;
    // EBPF_OP_LDDW pc=2982 dst=r1 src=r0 offset=0 imm=1600548962
#line 281 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
    // EBPF_OP_STXDW pc=2984 dst=r10 src=r1 offset=-112 imm=0
#line 281 "sample/undocked/map.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-112)) = (uint64_t)r1;
    // EBPF_OP_MOV64_REG pc=2985 dst=r1 src=r10 offset=0 imm=0
#line 281 "sample/undocked/map.c"
    r1 = r10;
    // EBPF_OP_ADD64_IMM pc=2986 dst=r1 src=r0 offset=0 imm=-112
#line 281 "sample/undocked/map.c"
    r1 += IMMEDIATE(-112);
    // EBPF_OP_MOV64_IMM pc=2987 dst=r2 src=r0 offset=0 imm=40
#line 281 "sample/undocked/map.c"
    r2 = IMMEDIATE(40);
    // EBPF_OP_MOV64_IMM pc=2988 dst=r4 src=r0 offset=0 imm=1
#line 281 "sample/undocked/map.c"
    r4 = IMMEDIATE(1);
    // EBPF_OP_JA pc=2989 dst=r0 src=r0 offset=-791 imm=0
#line 281 "sample/undocked/map.c"
    goto label_139;
label_184:
    // EBPF_OP_MOV64_IMM pc=2990 dst=r1 src=r0 offset=0 imm=0
#line 281 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=2991 dst=r10 src=r1 offset=-4 imm=0
#line 284 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_REG pc=2992 dst=r2 src=r10 offset=0 imm=0
#line 284 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=2993 dst=r2 src=r0 offset=0 imm=-4
#line 284 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=2994 dst=r1 src=r1 offset=0 imm=8
#line 284 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_CALL pc=2996 dst=r0 src=r0 offset=0 imm=18
#line 284 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[6].address(r1, r2, r3, r4, r5, context);
#line 284 "sample/undocked/map.c"
    if ((runtime_context->helper_data[6].tail_call) && (r0 == 0)) {
#line 284 "sample/undocked/map.c"
        return 0;
#line 284 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=2997 dst=r7 src=r0 offset=0 imm=0
#line 284 "sample/undocked/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=2998 dst=r4 src=r7 offset=0 imm=0
#line 284 "sample/undocked/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=2999 dst=r4 src=r0 offset=0 imm=32
#line 284 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=3000 dst=r1 src=r4 offset=0 imm=0
#line 284 "sample/undocked/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=3001 dst=r1 src=r0 offset=0 imm=32
#line 284 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_LDDW pc=3002 dst=r2 src=r0 offset=0 imm=-7
#line 284 "sample/undocked/map.c"
    r2 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=3004 dst=r1 src=r2 offset=1 imm=0
#line 284 "sample/undocked/map.c"
    if (r1 == r2) {
#line 284 "sample/undocked/map.c"
        goto label_185;
#line 284 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=3005 dst=r0 src=r0 offset=-1674 imm=0
#line 284 "sample/undocked/map.c"
    goto label_86;
label_185:
    // EBPF_OP_LDXW pc=3006 dst=r3 src=r10 offset=-4 imm=0
#line 284 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=3007 dst=r3 src=r0 offset=1 imm=0
#line 284 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(0)) {
#line 284 "sample/undocked/map.c"
        goto label_186;
#line 284 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=3008 dst=r0 src=r0 offset=-831 imm=0
#line 284 "sample/undocked/map.c"
    goto label_137;
label_186:
    // EBPF_OP_STXW pc=3009 dst=r10 src=r6 offset=-4 imm=0
#line 285 "sample/undocked/map.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r6;
    // EBPF_OP_MOV64_REG pc=3010 dst=r2 src=r10 offset=0 imm=0
#line 285 "sample/undocked/map.c"
    r2 = r10;
    // EBPF_OP_ADD64_IMM pc=3011 dst=r2 src=r0 offset=0 imm=-4
#line 285 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
    // EBPF_OP_LDDW pc=3012 dst=r1 src=r1 offset=0 imm=8
#line 285 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
    // EBPF_OP_CALL pc=3014 dst=r0 src=r0 offset=0 imm=17
#line 285 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[8].address(r1, r2, r3, r4, r5, context);
#line 285 "sample/undocked/map.c"
    if ((runtime_context->helper_data[8].tail_call) && (r0 == 0)) {
#line 285 "sample/undocked/map.c"
        return 0;
#line 285 "sample/undocked/map.c"
    }
    // EBPF_OP_MOV64_REG pc=3015 dst=r7 src=r0 offset=0 imm=0
#line 285 "sample/undocked/map.c"
    r7 = r0;
    // EBPF_OP_MOV64_REG pc=3016 dst=r4 src=r7 offset=0 imm=0
#line 285 "sample/undocked/map.c"
    r4 = r7;
    // EBPF_OP_LSH64_IMM pc=3017 dst=r4 src=r0 offset=0 imm=32
#line 285 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_MOV64_REG pc=3018 dst=r1 src=r4 offset=0 imm=0
#line 285 "sample/undocked/map.c"
    r1 = r4;
    // EBPF_OP_RSH64_IMM pc=3019 dst=r1 src=r0 offset=0 imm=32
#line 285 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_LDDW pc=3020 dst=r2 src=r0 offset=0 imm=-7
#line 285 "sample/undocked/map.c"
    r2 = (uint64_t)4294967289;
    // EBPF_OP_JEQ_REG pc=3022 dst=r1 src=r2 offset=1 imm=0
#line 285 "sample/undocked/map.c"
    if (r1 == r2) {
#line 285 "sample/undocked/map.c"
        goto label_187;
#line 285 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=3023 dst=r0 src=r0 offset=-781 imm=0
#line 285 "sample/undocked/map.c"
    goto label_142;
label_187:
    // EBPF_OP_LDXW pc=3024 dst=r3 src=r10 offset=-4 imm=0
#line 285 "sample/undocked/map.c"
    r3 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_JEQ_IMM pc=3025 dst=r3 src=r0 offset=-2924 imm=0
#line 285 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(0)) {
#line 285 "sample/undocked/map.c"
        goto label_9;
#line 285 "sample/undocked/map.c"
    }
    // EBPF_OP_JA pc=3026 dst=r0 src=r0 offset=-758 imm=0
#line 285 "sample/undocked/map.c"
    goto label_144;
#line 290 "sample/undocked/map.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        {1, 144, 144}, // Version header.
        test_maps,
        "sample~1",
        "sample_ext",
        "test_maps",
        test_maps_maps,
        8,
        test_maps_helpers,
        11,
        3027,
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
    version->minor = 21;
    version->revision = 0;
}

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = NULL;
    *count = 0;
}

metadata_table_t map_metadata_table = {
    sizeof(metadata_table_t),
    _get_programs,
    _get_maps,
    _get_hash,
    _get_version,
    _get_map_initial_values,
    _get_global_variable_sections,
};
