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
         10,                // Maximum number of entries allowed in the map.
         0,                 // Inner map index.
         LIBBPF_PIN_NONE,   // Pinning type for the map.
         0,                 // Identifier for a map template.
         0,                 // The id of the inner map template.
     },
     "HASH_map"},
    {{0, 0},
     {
         1,  // Current Version.
         80, // Struct size up to the last field.
         80, // Total struct size including padding.
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
    {{0, 0},
     {
         1,  // Current Version.
         80, // Struct size up to the last field.
         80, // Total struct size including padding.
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
    {{0, 0},
     {
         1,  // Current Version.
         80, // Struct size up to the last field.
         80, // Total struct size including padding.
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
    {{0, 0},
     {
         1,  // Current Version.
         80, // Struct size up to the last field.
         80, // Total struct size including padding.
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
    {{0, 0},
     {
         1,  // Current Version.
         80, // Struct size up to the last field.
         80, // Total struct size including padding.
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
    {{0, 0},
     {
         1,  // Current Version.
         80, // Struct size up to the last field.
         80, // Total struct size including padding.
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
    {{0, 0},
     {
         1,  // Current Version.
         80, // Struct size up to the last field.
         80, // Total struct size including padding.
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
#line 202 "sample/undocked/map.c"
{
#line 202 "sample/undocked/map.c"
    // Prologue.
#line 202 "sample/undocked/map.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 202 "sample/undocked/map.c"
    register uint64_t r0 = 0;
#line 202 "sample/undocked/map.c"
    register uint64_t r1 = 0;
#line 202 "sample/undocked/map.c"
    register uint64_t r2 = 0;
#line 202 "sample/undocked/map.c"
    register uint64_t r3 = 0;
#line 202 "sample/undocked/map.c"
    register uint64_t r4 = 0;
#line 202 "sample/undocked/map.c"
    register uint64_t r5 = 0;
#line 202 "sample/undocked/map.c"
    register uint64_t r6 = 0;
#line 202 "sample/undocked/map.c"
    register uint64_t r7 = 0;
#line 202 "sample/undocked/map.c"
    register uint64_t r8 = 0;
#line 202 "sample/undocked/map.c"
    register uint64_t r10 = 0;

#line 202 "sample/undocked/map.c"
    r1 = (uintptr_t)context;
#line 202 "sample/undocked/map.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

#line 202 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 70 "sample/undocked/map.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-64));
#line 70 "sample/undocked/map.c"
    r1 = IMMEDIATE(1);
#line 71 "sample/undocked/map.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
#line 71 "sample/undocked/map.c"
    r2 = r10;
#line 71 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
#line 71 "sample/undocked/map.c"
    r3 = r10;
#line 71 "sample/undocked/map.c"
    r3 += IMMEDIATE(-4);
#line 74 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[0].address);
#line 74 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
#line 74 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 74 "sample/undocked/map.c"
    r6 = r0;
#line 74 "sample/undocked/map.c"
    r3 = r6;
#line 74 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
#line 74 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
#line 75 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 75 "sample/undocked/map.c"
        goto label_2;
#line 75 "sample/undocked/map.c"
    }
label_1:
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
#line 75 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
#line 75 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671142817909;
#line 75 "sample/undocked/map.c"
    goto label_5;
label_2:
#line 75 "sample/undocked/map.c"
    r2 = r10;
#line 80 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
#line 80 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[0].address);
#line 80 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 81 "sample/undocked/map.c"
    if (r0 != IMMEDIATE(0)) {
#line 81 "sample/undocked/map.c"
        goto label_4;
#line 81 "sample/undocked/map.c"
    }
#line 81 "sample/undocked/map.c"
    r1 = IMMEDIATE(76);
#line 82 "sample/undocked/map.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-88));
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)5500388420933217906;
#line 82 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
#line 82 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)7304680770234183532;
#line 82 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
#line 82 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 82 "sample/undocked/map.c"
    r1 = r10;
#line 82 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
#line 82 "sample/undocked/map.c"
    r2 = IMMEDIATE(34);
label_3:
#line 82 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 82 "sample/undocked/map.c"
    r6 = (uint64_t)4294967295;
#line 82 "sample/undocked/map.c"
    goto label_6;
label_4:
#line 82 "sample/undocked/map.c"
    r2 = r10;
#line 86 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
#line 86 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[0].address);
#line 86 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
#line 86 "sample/undocked/map.c"
    r6 = r0;
#line 86 "sample/undocked/map.c"
    r3 = r6;
#line 86 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
#line 86 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
#line 87 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 87 "sample/undocked/map.c"
        goto label_9;
#line 87 "sample/undocked/map.c"
    }
#line 87 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
#line 88 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
#line 88 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671210448228;
label_5:
#line 88 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
#line 88 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 88 "sample/undocked/map.c"
    r1 = r10;
#line 88 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
#line 88 "sample/undocked/map.c"
    r2 = IMMEDIATE(32);
#line 88 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
label_6:
#line 88 "sample/undocked/map.c"
    r1 = IMMEDIATE(100);
#line 205 "sample/undocked/map.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-84));
#line 205 "sample/undocked/map.c"
    r1 = IMMEDIATE(622879845);
#line 205 "sample/undocked/map.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-88));
#line 205 "sample/undocked/map.c"
    r1 = (uint64_t)7958552634295722056;
#line 205 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 205 "sample/undocked/map.c"
    r1 = (uint64_t)5999155482795797792;
#line 205 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 205 "sample/undocked/map.c"
    r1 = (uint64_t)8245921731643003461;
#line 205 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 205 "sample/undocked/map.c"
    r1 = (uint64_t)5639992313069659476;
#line 205 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 205 "sample/undocked/map.c"
    r3 = r6;
#line 205 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
#line 205 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
#line 205 "sample/undocked/map.c"
    r1 = r10;
#line 205 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
#line 205 "sample/undocked/map.c"
    r2 = IMMEDIATE(38);
label_7:
#line 205 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
label_8:
#line 218 "sample/undocked/map.c"
    r0 = r6;
#line 218 "sample/undocked/map.c"
    return r0;
label_9:
#line 218 "sample/undocked/map.c"
    r2 = r10;
#line 92 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
#line 92 "sample/undocked/map.c"
    r3 = r10;
#line 92 "sample/undocked/map.c"
    r3 += IMMEDIATE(-4);
#line 92 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[0].address);
#line 92 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
#line 92 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 92 "sample/undocked/map.c"
    r6 = r0;
#line 92 "sample/undocked/map.c"
    r3 = r6;
#line 92 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
#line 92 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
#line 93 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 93 "sample/undocked/map.c"
        goto label_10;
#line 93 "sample/undocked/map.c"
    }
#line 93 "sample/undocked/map.c"
    goto label_1;
label_10:
#line 93 "sample/undocked/map.c"
    r2 = r10;
#line 103 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
#line 103 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[0].address);
#line 103 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[5].address(r1, r2, r3, r4, r5, context);
#line 104 "sample/undocked/map.c"
    if (r0 != IMMEDIATE(0)) {
#line 104 "sample/undocked/map.c"
        goto label_11;
#line 104 "sample/undocked/map.c"
    }
#line 104 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 105 "sample/undocked/map.c"
    WRITE_ONCE_8(r10, (uint8_t)r1, OFFSET(-76));
#line 105 "sample/undocked/map.c"
    r1 = IMMEDIATE(1280070990);
#line 105 "sample/undocked/map.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-80));
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)2334102031925867621;
#line 105 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)8223693201956233061;
#line 105 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)8387229063778886766;
#line 105 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)7016450394082471788;
#line 105 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
#line 105 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 105 "sample/undocked/map.c"
    r1 = r10;
#line 105 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
#line 105 "sample/undocked/map.c"
    r2 = IMMEDIATE(45);
#line 105 "sample/undocked/map.c"
    goto label_3;
label_11:
#line 105 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 70 "sample/undocked/map.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-64));
#line 70 "sample/undocked/map.c"
    r1 = IMMEDIATE(1);
#line 71 "sample/undocked/map.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
#line 71 "sample/undocked/map.c"
    r2 = r10;
#line 71 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
#line 71 "sample/undocked/map.c"
    r3 = r10;
#line 71 "sample/undocked/map.c"
    r3 += IMMEDIATE(-4);
#line 74 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[1].address);
#line 74 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
#line 74 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 74 "sample/undocked/map.c"
    r6 = r0;
#line 74 "sample/undocked/map.c"
    r3 = r6;
#line 74 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
#line 74 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
#line 75 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 75 "sample/undocked/map.c"
        goto label_13;
#line 75 "sample/undocked/map.c"
    }
label_12:
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
#line 75 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
#line 75 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671142817909;
#line 75 "sample/undocked/map.c"
    goto label_16;
label_13:
#line 75 "sample/undocked/map.c"
    r2 = r10;
#line 80 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
#line 80 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[1].address);
#line 80 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 81 "sample/undocked/map.c"
    if (r0 != IMMEDIATE(0)) {
#line 81 "sample/undocked/map.c"
        goto label_15;
#line 81 "sample/undocked/map.c"
    }
#line 81 "sample/undocked/map.c"
    r1 = IMMEDIATE(76);
#line 82 "sample/undocked/map.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-88));
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)5500388420933217906;
#line 82 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
#line 82 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)7304680770234183532;
#line 82 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
#line 82 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 82 "sample/undocked/map.c"
    r1 = r10;
#line 82 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
#line 82 "sample/undocked/map.c"
    r2 = IMMEDIATE(34);
label_14:
#line 82 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 82 "sample/undocked/map.c"
    r6 = (uint64_t)4294967295;
#line 82 "sample/undocked/map.c"
    goto label_17;
label_15:
#line 82 "sample/undocked/map.c"
    r2 = r10;
#line 86 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
#line 86 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[1].address);
#line 86 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
#line 86 "sample/undocked/map.c"
    r6 = r0;
#line 86 "sample/undocked/map.c"
    r3 = r6;
#line 86 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
#line 86 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
#line 87 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 87 "sample/undocked/map.c"
        goto label_18;
#line 87 "sample/undocked/map.c"
    }
#line 87 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
#line 88 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
#line 88 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671210448228;
label_16:
#line 88 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
#line 88 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 88 "sample/undocked/map.c"
    r1 = r10;
#line 88 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
#line 88 "sample/undocked/map.c"
    r2 = IMMEDIATE(32);
#line 88 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
label_17:
#line 88 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 206 "sample/undocked/map.c"
    WRITE_ONCE_8(r10, (uint8_t)r1, OFFSET(-76));
#line 206 "sample/undocked/map.c"
    r1 = IMMEDIATE(1680154724);
#line 206 "sample/undocked/map.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-80));
#line 206 "sample/undocked/map.c"
    r1 = (uint64_t)7308905094058439200;
#line 206 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
#line 206 "sample/undocked/map.c"
    r1 = (uint64_t)5211580972890673219;
#line 206 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 206 "sample/undocked/map.c"
    r1 = (uint64_t)5928232584757734688;
#line 206 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 206 "sample/undocked/map.c"
    r1 = (uint64_t)8245921731643003461;
#line 206 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 206 "sample/undocked/map.c"
    r1 = (uint64_t)5639992313069659476;
#line 206 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 206 "sample/undocked/map.c"
    r3 = r6;
#line 206 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
#line 206 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
#line 206 "sample/undocked/map.c"
    r1 = r10;
#line 206 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
#line 206 "sample/undocked/map.c"
    r2 = IMMEDIATE(45);
#line 206 "sample/undocked/map.c"
    goto label_7;
label_18:
#line 206 "sample/undocked/map.c"
    r2 = r10;
#line 92 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
#line 92 "sample/undocked/map.c"
    r3 = r10;
#line 92 "sample/undocked/map.c"
    r3 += IMMEDIATE(-4);
#line 92 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[1].address);
#line 92 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
#line 92 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 92 "sample/undocked/map.c"
    r6 = r0;
#line 92 "sample/undocked/map.c"
    r3 = r6;
#line 92 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
#line 92 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
#line 93 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 93 "sample/undocked/map.c"
        goto label_19;
#line 93 "sample/undocked/map.c"
    }
#line 93 "sample/undocked/map.c"
    goto label_12;
label_19:
#line 93 "sample/undocked/map.c"
    r2 = r10;
#line 103 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
#line 103 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[1].address);
#line 103 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[5].address(r1, r2, r3, r4, r5, context);
#line 104 "sample/undocked/map.c"
    if (r0 != IMMEDIATE(0)) {
#line 104 "sample/undocked/map.c"
        goto label_20;
#line 104 "sample/undocked/map.c"
    }
#line 104 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 105 "sample/undocked/map.c"
    WRITE_ONCE_8(r10, (uint8_t)r1, OFFSET(-76));
#line 105 "sample/undocked/map.c"
    r1 = IMMEDIATE(1280070990);
#line 105 "sample/undocked/map.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-80));
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)2334102031925867621;
#line 105 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)8223693201956233061;
#line 105 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)8387229063778886766;
#line 105 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)7016450394082471788;
#line 105 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
#line 105 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 105 "sample/undocked/map.c"
    r1 = r10;
#line 105 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
#line 105 "sample/undocked/map.c"
    r2 = IMMEDIATE(45);
#line 105 "sample/undocked/map.c"
    goto label_14;
label_20:
#line 105 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 70 "sample/undocked/map.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-64));
#line 70 "sample/undocked/map.c"
    r1 = IMMEDIATE(1);
#line 71 "sample/undocked/map.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
#line 71 "sample/undocked/map.c"
    r2 = r10;
#line 71 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
#line 71 "sample/undocked/map.c"
    r3 = r10;
#line 71 "sample/undocked/map.c"
    r3 += IMMEDIATE(-4);
#line 74 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[2].address);
#line 74 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
#line 74 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 74 "sample/undocked/map.c"
    r6 = r0;
#line 74 "sample/undocked/map.c"
    r3 = r6;
#line 74 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
#line 74 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
#line 75 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 75 "sample/undocked/map.c"
        goto label_22;
#line 75 "sample/undocked/map.c"
    }
label_21:
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
#line 75 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
#line 75 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671142817909;
#line 75 "sample/undocked/map.c"
    goto label_24;
label_22:
#line 75 "sample/undocked/map.c"
    r2 = r10;
#line 80 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
#line 80 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[2].address);
#line 80 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 81 "sample/undocked/map.c"
    if (r0 != IMMEDIATE(0)) {
#line 81 "sample/undocked/map.c"
        goto label_23;
#line 81 "sample/undocked/map.c"
    }
#line 81 "sample/undocked/map.c"
    r1 = IMMEDIATE(76);
#line 82 "sample/undocked/map.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-88));
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)5500388420933217906;
#line 82 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
#line 82 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)7304680770234183532;
#line 82 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
#line 82 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 82 "sample/undocked/map.c"
    r1 = r10;
#line 82 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
#line 82 "sample/undocked/map.c"
    r2 = IMMEDIATE(34);
#line 82 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 82 "sample/undocked/map.c"
    r6 = (uint64_t)4294967295;
#line 82 "sample/undocked/map.c"
    goto label_25;
label_23:
#line 82 "sample/undocked/map.c"
    r2 = r10;
#line 86 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
#line 86 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[2].address);
#line 86 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
#line 86 "sample/undocked/map.c"
    r6 = r0;
#line 86 "sample/undocked/map.c"
    r3 = r6;
#line 86 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
#line 86 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
#line 87 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 87 "sample/undocked/map.c"
        goto label_26;
#line 87 "sample/undocked/map.c"
    }
#line 87 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
#line 88 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
#line 88 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671210448228;
label_24:
#line 88 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
#line 88 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 88 "sample/undocked/map.c"
    r1 = r10;
#line 88 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
#line 88 "sample/undocked/map.c"
    r2 = IMMEDIATE(32);
#line 88 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
label_25:
#line 88 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 207 "sample/undocked/map.c"
    WRITE_ONCE_8(r10, (uint8_t)r1, OFFSET(-82));
#line 207 "sample/undocked/map.c"
    r1 = IMMEDIATE(25637);
#line 207 "sample/undocked/map.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-84));
#line 207 "sample/undocked/map.c"
    r1 = IMMEDIATE(543450478);
#line 207 "sample/undocked/map.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-88));
#line 207 "sample/undocked/map.c"
    r1 = (uint64_t)8247626271654172993;
#line 207 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 207 "sample/undocked/map.c"
    r1 = (uint64_t)5931875266780556576;
#line 207 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 207 "sample/undocked/map.c"
    r1 = (uint64_t)8245921731643003461;
#line 207 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 207 "sample/undocked/map.c"
    r1 = (uint64_t)5639992313069659476;
#line 207 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 207 "sample/undocked/map.c"
    r3 = r6;
#line 207 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
#line 207 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
#line 207 "sample/undocked/map.c"
    r1 = r10;
#line 207 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
#line 207 "sample/undocked/map.c"
    r2 = IMMEDIATE(39);
#line 207 "sample/undocked/map.c"
    goto label_7;
label_26:
#line 207 "sample/undocked/map.c"
    r2 = r10;
#line 92 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
#line 92 "sample/undocked/map.c"
    r3 = r10;
#line 92 "sample/undocked/map.c"
    r3 += IMMEDIATE(-4);
#line 92 "sample/undocked/map.c"
    r7 = IMMEDIATE(0);
#line 92 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[2].address);
#line 92 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
#line 92 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 92 "sample/undocked/map.c"
    r6 = r0;
#line 92 "sample/undocked/map.c"
    r3 = r6;
#line 92 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
#line 92 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
#line 93 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 93 "sample/undocked/map.c"
        goto label_27;
#line 93 "sample/undocked/map.c"
    }
#line 93 "sample/undocked/map.c"
    goto label_21;
label_27:
#line 70 "sample/undocked/map.c"
    WRITE_ONCE_32(r10, (uint32_t)r7, OFFSET(-64));
#line 70 "sample/undocked/map.c"
    r1 = IMMEDIATE(1);
#line 71 "sample/undocked/map.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
#line 71 "sample/undocked/map.c"
    r2 = r10;
#line 71 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
#line 71 "sample/undocked/map.c"
    r3 = r10;
#line 71 "sample/undocked/map.c"
    r3 += IMMEDIATE(-4);
#line 74 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[3].address);
#line 74 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
#line 74 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 74 "sample/undocked/map.c"
    r6 = r0;
#line 74 "sample/undocked/map.c"
    r3 = r6;
#line 74 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
#line 74 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
#line 75 "sample/undocked/map.c"
    if ((int64_t)r7 > (int64_t)r3) {
#line 75 "sample/undocked/map.c"
        goto label_30;
#line 75 "sample/undocked/map.c"
    }
#line 75 "sample/undocked/map.c"
    r2 = r10;
#line 80 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
#line 80 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[3].address);
#line 80 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 81 "sample/undocked/map.c"
    if (r0 != IMMEDIATE(0)) {
#line 81 "sample/undocked/map.c"
        goto label_28;
#line 81 "sample/undocked/map.c"
    }
#line 81 "sample/undocked/map.c"
    r1 = IMMEDIATE(76);
#line 82 "sample/undocked/map.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-88));
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)5500388420933217906;
#line 82 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
#line 82 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)7304680770234183532;
#line 82 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
#line 82 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 82 "sample/undocked/map.c"
    r1 = r10;
#line 82 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
#line 82 "sample/undocked/map.c"
    r2 = IMMEDIATE(34);
#line 82 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 82 "sample/undocked/map.c"
    r6 = (uint64_t)4294967295;
#line 82 "sample/undocked/map.c"
    goto label_32;
label_28:
#line 82 "sample/undocked/map.c"
    r2 = r10;
#line 86 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
#line 86 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[3].address);
#line 86 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
#line 86 "sample/undocked/map.c"
    r6 = r0;
#line 86 "sample/undocked/map.c"
    r3 = r6;
#line 86 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
#line 86 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
#line 87 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 87 "sample/undocked/map.c"
        goto label_29;
#line 87 "sample/undocked/map.c"
    }
#line 87 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
#line 88 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
#line 88 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671210448228;
#line 88 "sample/undocked/map.c"
    goto label_31;
label_29:
#line 88 "sample/undocked/map.c"
    r2 = r10;
#line 92 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
#line 92 "sample/undocked/map.c"
    r3 = r10;
#line 92 "sample/undocked/map.c"
    r3 += IMMEDIATE(-4);
#line 92 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[3].address);
#line 92 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
#line 92 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 92 "sample/undocked/map.c"
    r6 = r0;
#line 92 "sample/undocked/map.c"
    r3 = r6;
#line 92 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
#line 92 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
#line 93 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 93 "sample/undocked/map.c"
        goto label_33;
#line 93 "sample/undocked/map.c"
    }
label_30:
#line 93 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
#line 93 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 93 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
#line 93 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 93 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671142817909;
label_31:
#line 93 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 93 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
#line 93 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 93 "sample/undocked/map.c"
    r1 = r10;
#line 93 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
#line 93 "sample/undocked/map.c"
    r2 = IMMEDIATE(32);
#line 93 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
label_32:
#line 93 "sample/undocked/map.c"
    r1 = IMMEDIATE(100);
#line 208 "sample/undocked/map.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-76));
#line 208 "sample/undocked/map.c"
    r1 = IMMEDIATE(622879845);
#line 208 "sample/undocked/map.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-80));
#line 208 "sample/undocked/map.c"
    r1 = (uint64_t)7958552634295722073;
#line 208 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
#line 208 "sample/undocked/map.c"
    r1 = (uint64_t)4706915001281368131;
#line 208 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 208 "sample/undocked/map.c"
    r1 = (uint64_t)5928232584757734688;
#line 208 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 208 "sample/undocked/map.c"
    r1 = (uint64_t)8245921731643003461;
#line 208 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 208 "sample/undocked/map.c"
    r1 = (uint64_t)5639992313069659476;
#line 208 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 208 "sample/undocked/map.c"
    r3 = r6;
#line 208 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
#line 208 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
#line 208 "sample/undocked/map.c"
    r1 = r10;
#line 208 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
#line 208 "sample/undocked/map.c"
    r2 = IMMEDIATE(46);
#line 208 "sample/undocked/map.c"
    goto label_7;
label_33:
#line 70 "sample/undocked/map.c"
    WRITE_ONCE_32(r10, (uint32_t)r7, OFFSET(-64));
#line 70 "sample/undocked/map.c"
    r1 = IMMEDIATE(1);
#line 71 "sample/undocked/map.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
#line 71 "sample/undocked/map.c"
    r2 = r10;
#line 71 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
#line 71 "sample/undocked/map.c"
    r3 = r10;
#line 71 "sample/undocked/map.c"
    r3 += IMMEDIATE(-4);
#line 74 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[4].address);
#line 74 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
#line 74 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 74 "sample/undocked/map.c"
    r6 = r0;
#line 74 "sample/undocked/map.c"
    r3 = r6;
#line 74 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
#line 74 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
#line 75 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 75 "sample/undocked/map.c"
        goto label_35;
#line 75 "sample/undocked/map.c"
    }
label_34:
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
#line 75 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
#line 75 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671142817909;
#line 75 "sample/undocked/map.c"
    goto label_38;
label_35:
#line 75 "sample/undocked/map.c"
    r2 = r10;
#line 80 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
#line 80 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[4].address);
#line 80 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 81 "sample/undocked/map.c"
    if (r0 != IMMEDIATE(0)) {
#line 81 "sample/undocked/map.c"
        goto label_37;
#line 81 "sample/undocked/map.c"
    }
#line 81 "sample/undocked/map.c"
    r1 = IMMEDIATE(76);
#line 82 "sample/undocked/map.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-88));
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)5500388420933217906;
#line 82 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
#line 82 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)7304680770234183532;
#line 82 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
#line 82 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 82 "sample/undocked/map.c"
    r1 = r10;
#line 82 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
#line 82 "sample/undocked/map.c"
    r2 = IMMEDIATE(34);
label_36:
#line 82 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 82 "sample/undocked/map.c"
    r6 = (uint64_t)4294967295;
#line 82 "sample/undocked/map.c"
    goto label_39;
label_37:
#line 82 "sample/undocked/map.c"
    r2 = r10;
#line 86 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
#line 86 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[4].address);
#line 86 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
#line 86 "sample/undocked/map.c"
    r6 = r0;
#line 86 "sample/undocked/map.c"
    r3 = r6;
#line 86 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
#line 86 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
#line 87 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 87 "sample/undocked/map.c"
        goto label_40;
#line 87 "sample/undocked/map.c"
    }
#line 87 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
#line 88 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
#line 88 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671210448228;
label_38:
#line 88 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
#line 88 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 88 "sample/undocked/map.c"
    r1 = r10;
#line 88 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
#line 88 "sample/undocked/map.c"
    r2 = IMMEDIATE(32);
#line 88 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
label_39:
#line 88 "sample/undocked/map.c"
    r1 = IMMEDIATE(100);
#line 209 "sample/undocked/map.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-80));
#line 209 "sample/undocked/map.c"
    r1 = (uint64_t)2675248565465544052;
#line 209 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
#line 209 "sample/undocked/map.c"
    r1 = (uint64_t)7309940640182257759;
#line 209 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 209 "sample/undocked/map.c"
    r1 = (uint64_t)6148060143522245920;
#line 209 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 209 "sample/undocked/map.c"
    r1 = (uint64_t)8245921731643003461;
#line 209 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 209 "sample/undocked/map.c"
    r1 = (uint64_t)5639992313069659476;
#line 209 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 209 "sample/undocked/map.c"
    r3 = r6;
#line 209 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
#line 209 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
#line 209 "sample/undocked/map.c"
    r1 = r10;
#line 209 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
#line 209 "sample/undocked/map.c"
    r2 = IMMEDIATE(42);
#line 209 "sample/undocked/map.c"
    goto label_7;
label_40:
#line 209 "sample/undocked/map.c"
    r2 = r10;
#line 92 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
#line 92 "sample/undocked/map.c"
    r3 = r10;
#line 92 "sample/undocked/map.c"
    r3 += IMMEDIATE(-4);
#line 92 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[4].address);
#line 92 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
#line 92 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 92 "sample/undocked/map.c"
    r6 = r0;
#line 92 "sample/undocked/map.c"
    r3 = r6;
#line 92 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
#line 92 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
#line 93 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 93 "sample/undocked/map.c"
        goto label_41;
#line 93 "sample/undocked/map.c"
    }
#line 93 "sample/undocked/map.c"
    goto label_34;
label_41:
#line 93 "sample/undocked/map.c"
    r2 = r10;
#line 103 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
#line 103 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[4].address);
#line 103 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[5].address(r1, r2, r3, r4, r5, context);
#line 104 "sample/undocked/map.c"
    if (r0 != IMMEDIATE(0)) {
#line 104 "sample/undocked/map.c"
        goto label_42;
#line 104 "sample/undocked/map.c"
    }
#line 104 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 105 "sample/undocked/map.c"
    WRITE_ONCE_8(r10, (uint8_t)r1, OFFSET(-76));
#line 105 "sample/undocked/map.c"
    r1 = IMMEDIATE(1280070990);
#line 105 "sample/undocked/map.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-80));
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)2334102031925867621;
#line 105 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)8223693201956233061;
#line 105 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)8387229063778886766;
#line 105 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)7016450394082471788;
#line 105 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
#line 105 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 105 "sample/undocked/map.c"
    r1 = r10;
#line 105 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
#line 105 "sample/undocked/map.c"
    r2 = IMMEDIATE(45);
#line 105 "sample/undocked/map.c"
    goto label_36;
label_42:
#line 105 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 70 "sample/undocked/map.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-64));
#line 70 "sample/undocked/map.c"
    r1 = IMMEDIATE(1);
#line 71 "sample/undocked/map.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
#line 71 "sample/undocked/map.c"
    r2 = r10;
#line 71 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
#line 71 "sample/undocked/map.c"
    r3 = r10;
#line 71 "sample/undocked/map.c"
    r3 += IMMEDIATE(-4);
#line 74 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[5].address);
#line 74 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
#line 74 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 74 "sample/undocked/map.c"
    r6 = r0;
#line 74 "sample/undocked/map.c"
    r3 = r6;
#line 74 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
#line 74 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
#line 75 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 75 "sample/undocked/map.c"
        goto label_44;
#line 75 "sample/undocked/map.c"
    }
label_43:
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
#line 75 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
#line 75 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 75 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671142817909;
#line 75 "sample/undocked/map.c"
    goto label_47;
label_44:
#line 75 "sample/undocked/map.c"
    r2 = r10;
#line 80 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
#line 80 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[5].address);
#line 80 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
#line 81 "sample/undocked/map.c"
    if (r0 != IMMEDIATE(0)) {
#line 81 "sample/undocked/map.c"
        goto label_46;
#line 81 "sample/undocked/map.c"
    }
#line 81 "sample/undocked/map.c"
    r1 = IMMEDIATE(76);
#line 82 "sample/undocked/map.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-88));
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)5500388420933217906;
#line 82 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
#line 82 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)7304680770234183532;
#line 82 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 82 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
#line 82 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 82 "sample/undocked/map.c"
    r1 = r10;
#line 82 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
#line 82 "sample/undocked/map.c"
    r2 = IMMEDIATE(34);
label_45:
#line 82 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[2].address(r1, r2, r3, r4, r5, context);
#line 82 "sample/undocked/map.c"
    r6 = (uint64_t)4294967295;
#line 82 "sample/undocked/map.c"
    goto label_48;
label_46:
#line 82 "sample/undocked/map.c"
    r2 = r10;
#line 86 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
#line 86 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[5].address);
#line 86 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[3].address(r1, r2, r3, r4, r5, context);
#line 86 "sample/undocked/map.c"
    r6 = r0;
#line 86 "sample/undocked/map.c"
    r3 = r6;
#line 86 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
#line 86 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
#line 87 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 87 "sample/undocked/map.c"
        goto label_49;
#line 87 "sample/undocked/map.c"
    }
#line 87 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
#line 88 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140580722028;
#line 88 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)7304668671210448228;
label_47:
#line 88 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 88 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
#line 88 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 88 "sample/undocked/map.c"
    r1 = r10;
#line 88 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
#line 88 "sample/undocked/map.c"
    r2 = IMMEDIATE(32);
#line 88 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
label_48:
#line 88 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 210 "sample/undocked/map.c"
    WRITE_ONCE_8(r10, (uint8_t)r1, OFFSET(-72));
#line 210 "sample/undocked/map.c"
    r1 = (uint64_t)7216209593501643381;
#line 210 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-80));
#line 210 "sample/undocked/map.c"
    r1 = (uint64_t)8387235364025352520;
#line 210 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
#line 210 "sample/undocked/map.c"
    r1 = (uint64_t)6869485056696864863;
#line 210 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 210 "sample/undocked/map.c"
    r1 = (uint64_t)6148060143522245920;
#line 210 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 210 "sample/undocked/map.c"
    r1 = (uint64_t)8245921731643003461;
#line 210 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 210 "sample/undocked/map.c"
    r1 = (uint64_t)5639992313069659476;
#line 210 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 210 "sample/undocked/map.c"
    r3 = r6;
#line 210 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
#line 210 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
#line 210 "sample/undocked/map.c"
    r1 = r10;
#line 210 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
#line 210 "sample/undocked/map.c"
    r2 = IMMEDIATE(49);
#line 210 "sample/undocked/map.c"
    goto label_7;
label_49:
#line 210 "sample/undocked/map.c"
    r2 = r10;
#line 92 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
#line 92 "sample/undocked/map.c"
    r3 = r10;
#line 92 "sample/undocked/map.c"
    r3 += IMMEDIATE(-4);
#line 92 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[5].address);
#line 92 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
#line 92 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[0].address(r1, r2, r3, r4, r5, context);
#line 92 "sample/undocked/map.c"
    r6 = r0;
#line 92 "sample/undocked/map.c"
    r3 = r6;
#line 92 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
#line 92 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
#line 93 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 93 "sample/undocked/map.c"
        goto label_50;
#line 93 "sample/undocked/map.c"
    }
#line 93 "sample/undocked/map.c"
    goto label_43;
label_50:
#line 93 "sample/undocked/map.c"
    r2 = r10;
#line 103 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
#line 103 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[5].address);
#line 103 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[5].address(r1, r2, r3, r4, r5, context);
#line 104 "sample/undocked/map.c"
    if (r0 != IMMEDIATE(0)) {
#line 104 "sample/undocked/map.c"
        goto label_51;
#line 104 "sample/undocked/map.c"
    }
#line 104 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 105 "sample/undocked/map.c"
    WRITE_ONCE_8(r10, (uint8_t)r1, OFFSET(-76));
#line 105 "sample/undocked/map.c"
    r1 = IMMEDIATE(1280070990);
#line 105 "sample/undocked/map.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-80));
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)2334102031925867621;
#line 105 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)8223693201956233061;
#line 105 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)8387229063778886766;
#line 105 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)7016450394082471788;
#line 105 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 105 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
#line 105 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 105 "sample/undocked/map.c"
    r1 = r10;
#line 105 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
#line 105 "sample/undocked/map.c"
    r2 = IMMEDIATE(45);
#line 105 "sample/undocked/map.c"
    goto label_45;
label_51:
#line 105 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 176 "sample/undocked/map.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-64));
#line 176 "sample/undocked/map.c"
    r2 = r10;
#line 176 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
#line 176 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
#line 176 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[6].address(r1, r2, r3, r4, r5, context);
#line 176 "sample/undocked/map.c"
    r6 = r0;
#line 176 "sample/undocked/map.c"
    r4 = r6;
#line 176 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
#line 176 "sample/undocked/map.c"
    r1 = r4;
#line 176 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
#line 176 "sample/undocked/map.c"
    r2 = (uint64_t)4294967289;
#line 176 "sample/undocked/map.c"
    if (r1 == r2) {
#line 176 "sample/undocked/map.c"
        goto label_54;
#line 176 "sample/undocked/map.c"
    }
label_52:
#line 176 "sample/undocked/map.c"
    r1 = IMMEDIATE(100);
#line 176 "sample/undocked/map.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-72));
#line 176 "sample/undocked/map.c"
    r1 = (uint64_t)2675248565465544052;
#line 176 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-80));
#line 176 "sample/undocked/map.c"
    r1 = (uint64_t)7309940759667438700;
#line 176 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
#line 176 "sample/undocked/map.c"
    r1 = (uint64_t)8463219665603620457;
#line 176 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 176 "sample/undocked/map.c"
    r1 = (uint64_t)8386658464824631405;
#line 176 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 176 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755813578096;
#line 176 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 176 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
#line 176 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 176 "sample/undocked/map.c"
    r4 = (int64_t)r4 >> (uint32_t)(IMMEDIATE(32) & 63);
#line 176 "sample/undocked/map.c"
    r1 = r10;
#line 176 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
#line 176 "sample/undocked/map.c"
    r2 = IMMEDIATE(50);
label_53:
#line 176 "sample/undocked/map.c"
    r3 = IMMEDIATE(-7);
#line 176 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[7].address(r1, r2, r3, r4, r5, context);
#line 176 "sample/undocked/map.c"
    goto label_58;
label_54:
#line 176 "sample/undocked/map.c"
    READ_ONCE_32(r3, r10, OFFSET(-64));
#line 176 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(0)) {
#line 176 "sample/undocked/map.c"
        goto label_63;
#line 176 "sample/undocked/map.c"
    }
label_55:
#line 176 "sample/undocked/map.c"
    r1 = (uint64_t)7216209606537213027;
#line 176 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
#line 176 "sample/undocked/map.c"
    r1 = (uint64_t)7309474570952779040;
#line 176 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 176 "sample/undocked/map.c"
    r1 = (uint64_t)7958552634295722093;
#line 176 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 176 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755813578096;
#line 176 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 176 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
#line 176 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 176 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 176 "sample/undocked/map.c"
    WRITE_ONCE_8(r10, (uint8_t)r1, OFFSET(-80));
#line 176 "sample/undocked/map.c"
    r1 = r10;
#line 176 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
#line 176 "sample/undocked/map.c"
    r2 = IMMEDIATE(41);
label_56:
#line 176 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
label_57:
#line 176 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[7].address(r1, r2, r3, r4, r5, context);
#line 176 "sample/undocked/map.c"
    r6 = (uint64_t)4294967295;
label_58:
#line 215 "sample/undocked/map.c"
    r3 = r6;
#line 215 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
#line 215 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
#line 215 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 215 "sample/undocked/map.c"
        goto label_59;
#line 215 "sample/undocked/map.c"
    }
#line 215 "sample/undocked/map.c"
    goto label_62;
label_59:
#line 215 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 176 "sample/undocked/map.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-64));
#line 176 "sample/undocked/map.c"
    r2 = r10;
#line 176 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
#line 176 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
#line 176 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[6].address(r1, r2, r3, r4, r5, context);
#line 176 "sample/undocked/map.c"
    r7 = r0;
#line 176 "sample/undocked/map.c"
    r4 = r7;
#line 176 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
#line 176 "sample/undocked/map.c"
    r1 = r4;
#line 176 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
#line 176 "sample/undocked/map.c"
    r2 = (uint64_t)4294967289;
#line 176 "sample/undocked/map.c"
    if (r1 == r2) {
#line 176 "sample/undocked/map.c"
        goto label_86;
#line 176 "sample/undocked/map.c"
    }
label_60:
#line 176 "sample/undocked/map.c"
    r1 = IMMEDIATE(100);
#line 176 "sample/undocked/map.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-72));
#line 176 "sample/undocked/map.c"
    r1 = (uint64_t)2675248565465544052;
#line 176 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-80));
#line 176 "sample/undocked/map.c"
    r1 = (uint64_t)7309940759667438700;
#line 176 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
#line 176 "sample/undocked/map.c"
    r1 = (uint64_t)8463219665603620457;
#line 176 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 176 "sample/undocked/map.c"
    r1 = (uint64_t)8386658464824631405;
#line 176 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 176 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755813578096;
#line 176 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 176 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
#line 176 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 176 "sample/undocked/map.c"
    r4 = (int64_t)r4 >> (uint32_t)(IMMEDIATE(32) & 63);
#line 176 "sample/undocked/map.c"
    r1 = r10;
#line 176 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
#line 176 "sample/undocked/map.c"
    r2 = IMMEDIATE(50);
label_61:
#line 176 "sample/undocked/map.c"
    r3 = IMMEDIATE(-7);
#line 176 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[7].address(r1, r2, r3, r4, r5, context);
#line 176 "sample/undocked/map.c"
    goto label_90;
label_62:
#line 176 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
#line 215 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
#line 215 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140578096453;
#line 215 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 215 "sample/undocked/map.c"
    r1 = (uint64_t)6147730633380405362;
#line 215 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 215 "sample/undocked/map.c"
    r1 = (uint64_t)8027138915134627656;
#line 215 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 215 "sample/undocked/map.c"
    r1 = (uint64_t)6004793778491319636;
#line 215 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 215 "sample/undocked/map.c"
    r1 = r10;
#line 215 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
#line 215 "sample/undocked/map.c"
    r2 = IMMEDIATE(40);
#line 215 "sample/undocked/map.c"
    goto label_7;
label_63:
#line 177 "sample/undocked/map.c"
    WRITE_ONCE_32(r10, (uint32_t)r7, OFFSET(-64));
#line 177 "sample/undocked/map.c"
    r2 = r10;
#line 177 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
#line 177 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
#line 177 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[8].address(r1, r2, r3, r4, r5, context);
#line 177 "sample/undocked/map.c"
    r6 = r0;
#line 177 "sample/undocked/map.c"
    r4 = r6;
#line 177 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
#line 177 "sample/undocked/map.c"
    r1 = r4;
#line 177 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
#line 177 "sample/undocked/map.c"
    r2 = (uint64_t)4294967289;
#line 177 "sample/undocked/map.c"
    if (r1 == r2) {
#line 177 "sample/undocked/map.c"
        goto label_65;
#line 177 "sample/undocked/map.c"
    }
label_64:
#line 177 "sample/undocked/map.c"
    WRITE_ONCE_8(r10, (uint8_t)r7, OFFSET(-72));
#line 177 "sample/undocked/map.c"
    r1 = (uint64_t)7216209593501643381;
#line 177 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-80));
#line 177 "sample/undocked/map.c"
    r1 = (uint64_t)8387235364492091508;
#line 177 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
#line 177 "sample/undocked/map.c"
    r1 = (uint64_t)7815279607914981230;
#line 177 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 177 "sample/undocked/map.c"
    r1 = (uint64_t)7598807758610654496;
#line 177 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 177 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
#line 177 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 177 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
#line 177 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 177 "sample/undocked/map.c"
    r4 = (int64_t)r4 >> (uint32_t)(IMMEDIATE(32) & 63);
#line 177 "sample/undocked/map.c"
    r1 = r10;
#line 177 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
#line 177 "sample/undocked/map.c"
    r2 = IMMEDIATE(49);
#line 177 "sample/undocked/map.c"
    goto label_53;
label_65:
#line 177 "sample/undocked/map.c"
    READ_ONCE_32(r3, r10, OFFSET(-64));
#line 177 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(0)) {
#line 177 "sample/undocked/map.c"
        goto label_67;
#line 177 "sample/undocked/map.c"
    }
label_66:
#line 177 "sample/undocked/map.c"
    r1 = (uint64_t)28188318775535988;
#line 177 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
#line 177 "sample/undocked/map.c"
    r1 = (uint64_t)7162254444797649957;
#line 177 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 177 "sample/undocked/map.c"
    r1 = (uint64_t)2336931105441411616;
#line 177 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 177 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
#line 177 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 177 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
#line 177 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 177 "sample/undocked/map.c"
    r1 = r10;
#line 177 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
#line 177 "sample/undocked/map.c"
    r2 = IMMEDIATE(40);
#line 177 "sample/undocked/map.c"
    goto label_56;
label_67:
#line 177 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 181 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-64));
#line 181 "sample/undocked/map.c"
    READ_ONCE_64(r1, r10, OFFSET(-64));
#line 181 "sample/undocked/map.c"
    if (r1 > IMMEDIATE(9)) {
#line 181 "sample/undocked/map.c"
        goto label_69;
#line 181 "sample/undocked/map.c"
    }
#line 181 "sample/undocked/map.c"
    r7 = IMMEDIATE(10);
label_68:
#line 182 "sample/undocked/map.c"
    READ_ONCE_64(r1, r10, OFFSET(-64));
#line 182 "sample/undocked/map.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
#line 182 "sample/undocked/map.c"
    r2 = r10;
#line 182 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
#line 182 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
#line 182 "sample/undocked/map.c"
    r3 = IMMEDIATE(0);
#line 182 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[9].address(r1, r2, r3, r4, r5, context);
#line 182 "sample/undocked/map.c"
    r6 = r0;
#line 182 "sample/undocked/map.c"
    r5 = r6;
#line 182 "sample/undocked/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
#line 182 "sample/undocked/map.c"
    r1 = r5;
#line 182 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
#line 182 "sample/undocked/map.c"
    if (r1 != IMMEDIATE(0)) {
#line 182 "sample/undocked/map.c"
        goto label_71;
#line 182 "sample/undocked/map.c"
    }
#line 181 "sample/undocked/map.c"
    READ_ONCE_64(r1, r10, OFFSET(-64));
#line 181 "sample/undocked/map.c"
    r1 += IMMEDIATE(1);
#line 181 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-64));
#line 181 "sample/undocked/map.c"
    READ_ONCE_64(r1, r10, OFFSET(-64));
#line 181 "sample/undocked/map.c"
    if (r7 > r1) {
#line 181 "sample/undocked/map.c"
        goto label_68;
#line 181 "sample/undocked/map.c"
    }
label_69:
#line 181 "sample/undocked/map.c"
    r7 = IMMEDIATE(10);
#line 185 "sample/undocked/map.c"
    WRITE_ONCE_32(r10, (uint32_t)r7, OFFSET(-64));
#line 185 "sample/undocked/map.c"
    r2 = r10;
#line 185 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
#line 185 "sample/undocked/map.c"
    r8 = IMMEDIATE(0);
#line 185 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
#line 185 "sample/undocked/map.c"
    r3 = IMMEDIATE(0);
#line 185 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[9].address(r1, r2, r3, r4, r5, context);
#line 185 "sample/undocked/map.c"
    r6 = r0;
#line 185 "sample/undocked/map.c"
    r5 = r6;
#line 185 "sample/undocked/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
#line 185 "sample/undocked/map.c"
    r1 = r5;
#line 185 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
#line 185 "sample/undocked/map.c"
    r2 = (uint64_t)4294967267;
#line 185 "sample/undocked/map.c"
    if (r1 == r2) {
#line 185 "sample/undocked/map.c"
        goto label_70;
#line 185 "sample/undocked/map.c"
    }
#line 185 "sample/undocked/map.c"
    WRITE_ONCE_8(r10, (uint8_t)r8, OFFSET(-66));
#line 185 "sample/undocked/map.c"
    r1 = IMMEDIATE(25637);
#line 185 "sample/undocked/map.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-68));
#line 185 "sample/undocked/map.c"
    r1 = IMMEDIATE(543450478);
#line 185 "sample/undocked/map.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-72));
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)8247626271654175781;
#line 185 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-80));
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)2334102057442963576;
#line 185 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)7286934307705679465;
#line 185 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)8390880602192683117;
#line 185 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755764168048;
#line 185 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
#line 185 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 185 "sample/undocked/map.c"
    READ_ONCE_32(r3, r10, OFFSET(-64));
#line 185 "sample/undocked/map.c"
    r5 = (int64_t)r5 >> (uint32_t)(IMMEDIATE(32) & 63);
#line 185 "sample/undocked/map.c"
    r1 = r10;
#line 185 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
#line 185 "sample/undocked/map.c"
    r2 = IMMEDIATE(55);
#line 185 "sample/undocked/map.c"
    r4 = IMMEDIATE(-29);
#line 185 "sample/undocked/map.c"
    goto label_73;
label_70:
#line 186 "sample/undocked/map.c"
    WRITE_ONCE_32(r10, (uint32_t)r7, OFFSET(-64));
#line 186 "sample/undocked/map.c"
    r2 = r10;
#line 186 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
#line 186 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
#line 186 "sample/undocked/map.c"
    r3 = IMMEDIATE(2);
#line 186 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[9].address(r1, r2, r3, r4, r5, context);
#line 186 "sample/undocked/map.c"
    r6 = r0;
#line 186 "sample/undocked/map.c"
    r5 = r6;
#line 186 "sample/undocked/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
#line 186 "sample/undocked/map.c"
    r1 = r5;
#line 186 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
#line 186 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 186 "sample/undocked/map.c"
        goto label_74;
#line 186 "sample/undocked/map.c"
    }
#line 186 "sample/undocked/map.c"
    r1 = IMMEDIATE(25637);
#line 186 "sample/undocked/map.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-68));
#line 186 "sample/undocked/map.c"
    r1 = IMMEDIATE(543450478);
#line 186 "sample/undocked/map.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-72));
#line 186 "sample/undocked/map.c"
    r1 = (uint64_t)8247626271654175781;
#line 186 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-80));
#line 186 "sample/undocked/map.c"
    r1 = (uint64_t)2334102057442963576;
#line 186 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
#line 186 "sample/undocked/map.c"
    r1 = (uint64_t)7286934307705679465;
#line 186 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 186 "sample/undocked/map.c"
    r1 = (uint64_t)8390880602192683117;
#line 186 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 186 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755764168048;
#line 186 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 186 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
#line 186 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 186 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 186 "sample/undocked/map.c"
    WRITE_ONCE_8(r10, (uint8_t)r1, OFFSET(-66));
#line 186 "sample/undocked/map.c"
    READ_ONCE_32(r3, r10, OFFSET(-64));
#line 186 "sample/undocked/map.c"
    goto label_72;
label_71:
#line 186 "sample/undocked/map.c"
    r1 = IMMEDIATE(25637);
#line 182 "sample/undocked/map.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-68));
#line 182 "sample/undocked/map.c"
    r1 = IMMEDIATE(543450478);
#line 182 "sample/undocked/map.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-72));
#line 182 "sample/undocked/map.c"
    r1 = (uint64_t)8247626271654175781;
#line 182 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-80));
#line 182 "sample/undocked/map.c"
    r1 = (uint64_t)2334102057442963576;
#line 182 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
#line 182 "sample/undocked/map.c"
    r1 = (uint64_t)7286934307705679465;
#line 182 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 182 "sample/undocked/map.c"
    r1 = (uint64_t)8390880602192683117;
#line 182 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 182 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755764168048;
#line 182 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 182 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
#line 182 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 182 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 182 "sample/undocked/map.c"
    WRITE_ONCE_8(r10, (uint8_t)r1, OFFSET(-66));
#line 182 "sample/undocked/map.c"
    READ_ONCE_32(r3, r10, OFFSET(-4));
label_72:
#line 182 "sample/undocked/map.c"
    r5 = (int64_t)r5 >> (uint32_t)(IMMEDIATE(32) & 63);
#line 182 "sample/undocked/map.c"
    r1 = r10;
#line 182 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
#line 182 "sample/undocked/map.c"
    r2 = IMMEDIATE(55);
#line 182 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
label_73:
#line 182 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[10].address(r1, r2, r3, r4, r5, context);
#line 182 "sample/undocked/map.c"
    goto label_58;
label_74:
#line 182 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 188 "sample/undocked/map.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-64));
#line 188 "sample/undocked/map.c"
    r2 = r10;
#line 188 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
#line 188 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
#line 188 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[6].address(r1, r2, r3, r4, r5, context);
#line 188 "sample/undocked/map.c"
    r6 = r0;
#line 188 "sample/undocked/map.c"
    r4 = r6;
#line 188 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
#line 188 "sample/undocked/map.c"
    r1 = r4;
#line 188 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
#line 188 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 188 "sample/undocked/map.c"
        goto label_76;
#line 188 "sample/undocked/map.c"
    }
#line 188 "sample/undocked/map.c"
    r1 = IMMEDIATE(100);
#line 188 "sample/undocked/map.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-72));
#line 188 "sample/undocked/map.c"
    r1 = (uint64_t)2675248565465544052;
#line 188 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-80));
#line 188 "sample/undocked/map.c"
    r1 = (uint64_t)7309940759667438700;
#line 188 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
#line 188 "sample/undocked/map.c"
    r1 = (uint64_t)8463219665603620457;
#line 188 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 188 "sample/undocked/map.c"
    r1 = (uint64_t)8386658464824631405;
#line 188 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 188 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755813578096;
#line 188 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 188 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
#line 188 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 188 "sample/undocked/map.c"
    r4 = (int64_t)r4 >> (uint32_t)(IMMEDIATE(32) & 63);
#line 188 "sample/undocked/map.c"
    r1 = r10;
#line 188 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
#line 188 "sample/undocked/map.c"
    r2 = IMMEDIATE(50);
label_75:
#line 188 "sample/undocked/map.c"
    r3 = IMMEDIATE(0);
#line 188 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[7].address(r1, r2, r3, r4, r5, context);
#line 188 "sample/undocked/map.c"
    goto label_58;
label_76:
#line 188 "sample/undocked/map.c"
    READ_ONCE_32(r3, r10, OFFSET(-64));
#line 188 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(1)) {
#line 188 "sample/undocked/map.c"
        goto label_77;
#line 188 "sample/undocked/map.c"
    }
#line 188 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 188 "sample/undocked/map.c"
    WRITE_ONCE_8(r10, (uint8_t)r1, OFFSET(-80));
#line 188 "sample/undocked/map.c"
    r1 = (uint64_t)7216209606537213027;
#line 188 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
#line 188 "sample/undocked/map.c"
    r1 = (uint64_t)7309474570952779040;
#line 188 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 188 "sample/undocked/map.c"
    r1 = (uint64_t)7958552634295722093;
#line 188 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 188 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755813578096;
#line 188 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 188 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
#line 188 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 188 "sample/undocked/map.c"
    r1 = r10;
#line 188 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
#line 188 "sample/undocked/map.c"
    r2 = IMMEDIATE(41);
#line 188 "sample/undocked/map.c"
    r4 = IMMEDIATE(1);
#line 188 "sample/undocked/map.c"
    goto label_57;
label_77:
#line 188 "sample/undocked/map.c"
    r7 = IMMEDIATE(0);
#line 192 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r7, OFFSET(-64));
#line 192 "sample/undocked/map.c"
    READ_ONCE_64(r1, r10, OFFSET(-64));
#line 192 "sample/undocked/map.c"
    if (r1 > IMMEDIATE(9)) {
#line 192 "sample/undocked/map.c"
        goto label_79;
#line 192 "sample/undocked/map.c"
    }
#line 192 "sample/undocked/map.c"
    r8 = IMMEDIATE(10);
#line 192 "sample/undocked/map.c"
    goto label_80;
label_78:
#line 192 "sample/undocked/map.c"
    READ_ONCE_64(r1, r10, OFFSET(-64));
#line 192 "sample/undocked/map.c"
    r1 += IMMEDIATE(1);
#line 192 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-64));
#line 192 "sample/undocked/map.c"
    READ_ONCE_64(r1, r10, OFFSET(-64));
#line 192 "sample/undocked/map.c"
    if (r8 > r1) {
#line 192 "sample/undocked/map.c"
        goto label_80;
#line 192 "sample/undocked/map.c"
    }
label_79:
#line 196 "sample/undocked/map.c"
    WRITE_ONCE_32(r10, (uint32_t)r7, OFFSET(-64));
#line 196 "sample/undocked/map.c"
    r2 = r10;
#line 196 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
#line 196 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
#line 196 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[6].address(r1, r2, r3, r4, r5, context);
#line 196 "sample/undocked/map.c"
    r6 = r0;
#line 196 "sample/undocked/map.c"
    r4 = r6;
#line 196 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
#line 196 "sample/undocked/map.c"
    r1 = r4;
#line 196 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
#line 196 "sample/undocked/map.c"
    r2 = (uint64_t)4294967289;
#line 196 "sample/undocked/map.c"
    if (r1 == r2) {
#line 196 "sample/undocked/map.c"
        goto label_82;
#line 196 "sample/undocked/map.c"
    }
#line 196 "sample/undocked/map.c"
    goto label_52;
label_80:
#line 193 "sample/undocked/map.c"
    WRITE_ONCE_32(r10, (uint32_t)r7, OFFSET(-4));
#line 193 "sample/undocked/map.c"
    r2 = r10;
#line 193 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
#line 193 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
#line 193 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[8].address(r1, r2, r3, r4, r5, context);
#line 193 "sample/undocked/map.c"
    r6 = r0;
#line 193 "sample/undocked/map.c"
    r4 = r6;
#line 193 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
#line 193 "sample/undocked/map.c"
    r1 = r4;
#line 193 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
#line 193 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 193 "sample/undocked/map.c"
        goto label_81;
#line 193 "sample/undocked/map.c"
    }
#line 193 "sample/undocked/map.c"
    goto label_83;
label_81:
#line 193 "sample/undocked/map.c"
    READ_ONCE_64(r1, r10, OFFSET(-64));
#line 193 "sample/undocked/map.c"
    r1 += IMMEDIATE(1);
#line 193 "sample/undocked/map.c"
    READ_ONCE_32(r3, r10, OFFSET(-4));
#line 193 "sample/undocked/map.c"
    if (r1 == r3) {
#line 193 "sample/undocked/map.c"
        goto label_78;
#line 193 "sample/undocked/map.c"
    }
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)28188318775535988;
#line 193 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)7162254444797649957;
#line 193 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)2336931105441411616;
#line 193 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
#line 193 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
#line 193 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 193 "sample/undocked/map.c"
    READ_ONCE_64(r4, r10, OFFSET(-64));
#line 193 "sample/undocked/map.c"
    r4 += IMMEDIATE(1);
#line 193 "sample/undocked/map.c"
    r1 = r10;
#line 193 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
#line 193 "sample/undocked/map.c"
    r2 = IMMEDIATE(40);
#line 193 "sample/undocked/map.c"
    goto label_57;
label_82:
#line 196 "sample/undocked/map.c"
    READ_ONCE_32(r3, r10, OFFSET(-64));
#line 196 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(0)) {
#line 196 "sample/undocked/map.c"
        goto label_84;
#line 196 "sample/undocked/map.c"
    }
#line 196 "sample/undocked/map.c"
    goto label_55;
label_83:
#line 196 "sample/undocked/map.c"
    r1 = (uint64_t)7216209593501643381;
#line 193 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-80));
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)8387235364492091508;
#line 193 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)7815279607914981230;
#line 193 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)7598807758610654496;
#line 193 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
#line 193 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
#line 193 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 193 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 193 "sample/undocked/map.c"
    WRITE_ONCE_8(r10, (uint8_t)r1, OFFSET(-72));
#line 193 "sample/undocked/map.c"
    r4 = (int64_t)r4 >> (uint32_t)(IMMEDIATE(32) & 63);
#line 193 "sample/undocked/map.c"
    r1 = r10;
#line 193 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
#line 193 "sample/undocked/map.c"
    r2 = IMMEDIATE(49);
#line 193 "sample/undocked/map.c"
    goto label_75;
label_84:
#line 193 "sample/undocked/map.c"
    r7 = IMMEDIATE(0);
#line 197 "sample/undocked/map.c"
    WRITE_ONCE_32(r10, (uint32_t)r7, OFFSET(-64));
#line 197 "sample/undocked/map.c"
    r2 = r10;
#line 197 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
#line 197 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[6].address);
#line 197 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[8].address(r1, r2, r3, r4, r5, context);
#line 197 "sample/undocked/map.c"
    r6 = r0;
#line 197 "sample/undocked/map.c"
    r4 = r6;
#line 197 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
#line 197 "sample/undocked/map.c"
    r1 = r4;
#line 197 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
#line 197 "sample/undocked/map.c"
    r2 = (uint64_t)4294967289;
#line 197 "sample/undocked/map.c"
    if (r1 == r2) {
#line 197 "sample/undocked/map.c"
        goto label_85;
#line 197 "sample/undocked/map.c"
    }
#line 197 "sample/undocked/map.c"
    goto label_64;
label_85:
#line 197 "sample/undocked/map.c"
    READ_ONCE_32(r3, r10, OFFSET(-64));
#line 197 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(0)) {
#line 197 "sample/undocked/map.c"
        goto label_59;
#line 197 "sample/undocked/map.c"
    }
#line 197 "sample/undocked/map.c"
    goto label_66;
label_86:
#line 176 "sample/undocked/map.c"
    READ_ONCE_32(r3, r10, OFFSET(-64));
#line 176 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(0)) {
#line 176 "sample/undocked/map.c"
        goto label_91;
#line 176 "sample/undocked/map.c"
    }
label_87:
#line 176 "sample/undocked/map.c"
    r1 = (uint64_t)7216209606537213027;
#line 176 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
#line 176 "sample/undocked/map.c"
    r1 = (uint64_t)7309474570952779040;
#line 176 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 176 "sample/undocked/map.c"
    r1 = (uint64_t)7958552634295722093;
#line 176 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 176 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755813578096;
#line 176 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 176 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
#line 176 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 176 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 176 "sample/undocked/map.c"
    WRITE_ONCE_8(r10, (uint8_t)r1, OFFSET(-80));
#line 176 "sample/undocked/map.c"
    r1 = r10;
#line 176 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
#line 176 "sample/undocked/map.c"
    r2 = IMMEDIATE(41);
label_88:
#line 176 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
label_89:
#line 176 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[7].address(r1, r2, r3, r4, r5, context);
#line 176 "sample/undocked/map.c"
    r7 = (uint64_t)4294967295;
label_90:
#line 176 "sample/undocked/map.c"
    r6 = IMMEDIATE(0);
#line 216 "sample/undocked/map.c"
    r3 = r7;
#line 216 "sample/undocked/map.c"
    r3 <<= (IMMEDIATE(32) & 63);
#line 216 "sample/undocked/map.c"
    r3 = (int64_t)r3 >> (uint32_t)(IMMEDIATE(32) & 63);
#line 216 "sample/undocked/map.c"
    if ((int64_t)r3 > IMMEDIATE(-1)) {
#line 216 "sample/undocked/map.c"
        goto label_8;
#line 216 "sample/undocked/map.c"
    }
#line 216 "sample/undocked/map.c"
    r1 = (uint64_t)28188318724615794;
#line 216 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
#line 216 "sample/undocked/map.c"
    r1 = (uint64_t)8463501140578485057;
#line 216 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 216 "sample/undocked/map.c"
    r1 = (uint64_t)6076235989295898738;
#line 216 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 216 "sample/undocked/map.c"
    r1 = (uint64_t)8027138915134627656;
#line 216 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 216 "sample/undocked/map.c"
    r1 = (uint64_t)6004793778491319636;
#line 216 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 216 "sample/undocked/map.c"
    r1 = r10;
#line 216 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
#line 216 "sample/undocked/map.c"
    r2 = IMMEDIATE(40);
#line 216 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
#line 216 "sample/undocked/map.c"
    r6 = r7;
#line 216 "sample/undocked/map.c"
    goto label_8;
label_91:
#line 216 "sample/undocked/map.c"
    r6 = IMMEDIATE(0);
#line 177 "sample/undocked/map.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-64));
#line 177 "sample/undocked/map.c"
    r2 = r10;
#line 177 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
#line 177 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
#line 177 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[8].address(r1, r2, r3, r4, r5, context);
#line 177 "sample/undocked/map.c"
    r7 = r0;
#line 177 "sample/undocked/map.c"
    r4 = r7;
#line 177 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
#line 177 "sample/undocked/map.c"
    r1 = r4;
#line 177 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
#line 177 "sample/undocked/map.c"
    r2 = (uint64_t)4294967289;
#line 177 "sample/undocked/map.c"
    if (r1 == r2) {
#line 177 "sample/undocked/map.c"
        goto label_93;
#line 177 "sample/undocked/map.c"
    }
label_92:
#line 177 "sample/undocked/map.c"
    WRITE_ONCE_8(r10, (uint8_t)r6, OFFSET(-72));
#line 177 "sample/undocked/map.c"
    r1 = (uint64_t)7216209593501643381;
#line 177 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-80));
#line 177 "sample/undocked/map.c"
    r1 = (uint64_t)8387235364492091508;
#line 177 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
#line 177 "sample/undocked/map.c"
    r1 = (uint64_t)7815279607914981230;
#line 177 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 177 "sample/undocked/map.c"
    r1 = (uint64_t)7598807758610654496;
#line 177 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 177 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
#line 177 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 177 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
#line 177 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 177 "sample/undocked/map.c"
    r4 = (int64_t)r4 >> (uint32_t)(IMMEDIATE(32) & 63);
#line 177 "sample/undocked/map.c"
    r1 = r10;
#line 177 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
#line 177 "sample/undocked/map.c"
    r2 = IMMEDIATE(49);
#line 177 "sample/undocked/map.c"
    goto label_61;
label_93:
#line 177 "sample/undocked/map.c"
    READ_ONCE_32(r3, r10, OFFSET(-64));
#line 177 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(0)) {
#line 177 "sample/undocked/map.c"
        goto label_95;
#line 177 "sample/undocked/map.c"
    }
label_94:
#line 177 "sample/undocked/map.c"
    r1 = (uint64_t)28188318775535988;
#line 177 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
#line 177 "sample/undocked/map.c"
    r1 = (uint64_t)7162254444797649957;
#line 177 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 177 "sample/undocked/map.c"
    r1 = (uint64_t)2336931105441411616;
#line 177 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 177 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
#line 177 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 177 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
#line 177 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 177 "sample/undocked/map.c"
    r1 = r10;
#line 177 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
#line 177 "sample/undocked/map.c"
    r2 = IMMEDIATE(40);
#line 177 "sample/undocked/map.c"
    goto label_88;
label_95:
#line 177 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 181 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-64));
#line 181 "sample/undocked/map.c"
    READ_ONCE_64(r1, r10, OFFSET(-64));
#line 181 "sample/undocked/map.c"
    if (r1 > IMMEDIATE(9)) {
#line 181 "sample/undocked/map.c"
        goto label_97;
#line 181 "sample/undocked/map.c"
    }
#line 181 "sample/undocked/map.c"
    r6 = IMMEDIATE(10);
label_96:
#line 182 "sample/undocked/map.c"
    READ_ONCE_64(r1, r10, OFFSET(-64));
#line 182 "sample/undocked/map.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-4));
#line 182 "sample/undocked/map.c"
    r2 = r10;
#line 182 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
#line 182 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
#line 182 "sample/undocked/map.c"
    r3 = IMMEDIATE(0);
#line 182 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[9].address(r1, r2, r3, r4, r5, context);
#line 182 "sample/undocked/map.c"
    r7 = r0;
#line 182 "sample/undocked/map.c"
    r5 = r7;
#line 182 "sample/undocked/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
#line 182 "sample/undocked/map.c"
    r1 = r5;
#line 182 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
#line 182 "sample/undocked/map.c"
    if (r1 != IMMEDIATE(0)) {
#line 182 "sample/undocked/map.c"
        goto label_99;
#line 182 "sample/undocked/map.c"
    }
#line 181 "sample/undocked/map.c"
    READ_ONCE_64(r1, r10, OFFSET(-64));
#line 181 "sample/undocked/map.c"
    r1 += IMMEDIATE(1);
#line 181 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-64));
#line 181 "sample/undocked/map.c"
    READ_ONCE_64(r1, r10, OFFSET(-64));
#line 181 "sample/undocked/map.c"
    if (r6 > r1) {
#line 181 "sample/undocked/map.c"
        goto label_96;
#line 181 "sample/undocked/map.c"
    }
label_97:
#line 181 "sample/undocked/map.c"
    r6 = IMMEDIATE(10);
#line 185 "sample/undocked/map.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-64));
#line 185 "sample/undocked/map.c"
    r2 = r10;
#line 185 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
#line 185 "sample/undocked/map.c"
    r8 = IMMEDIATE(0);
#line 185 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
#line 185 "sample/undocked/map.c"
    r3 = IMMEDIATE(0);
#line 185 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[9].address(r1, r2, r3, r4, r5, context);
#line 185 "sample/undocked/map.c"
    r7 = r0;
#line 185 "sample/undocked/map.c"
    r5 = r7;
#line 185 "sample/undocked/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
#line 185 "sample/undocked/map.c"
    r1 = r5;
#line 185 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
#line 185 "sample/undocked/map.c"
    r2 = (uint64_t)4294967267;
#line 185 "sample/undocked/map.c"
    if (r1 == r2) {
#line 185 "sample/undocked/map.c"
        goto label_98;
#line 185 "sample/undocked/map.c"
    }
#line 185 "sample/undocked/map.c"
    WRITE_ONCE_8(r10, (uint8_t)r8, OFFSET(-66));
#line 185 "sample/undocked/map.c"
    r1 = IMMEDIATE(25637);
#line 185 "sample/undocked/map.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-68));
#line 185 "sample/undocked/map.c"
    r1 = IMMEDIATE(543450478);
#line 185 "sample/undocked/map.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-72));
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)8247626271654175781;
#line 185 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-80));
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)2334102057442963576;
#line 185 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)7286934307705679465;
#line 185 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)8390880602192683117;
#line 185 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755764168048;
#line 185 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 185 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
#line 185 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 185 "sample/undocked/map.c"
    READ_ONCE_32(r3, r10, OFFSET(-64));
#line 185 "sample/undocked/map.c"
    r5 = (int64_t)r5 >> (uint32_t)(IMMEDIATE(32) & 63);
#line 185 "sample/undocked/map.c"
    r1 = r10;
#line 185 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
#line 185 "sample/undocked/map.c"
    r2 = IMMEDIATE(55);
#line 185 "sample/undocked/map.c"
    r4 = IMMEDIATE(-29);
#line 185 "sample/undocked/map.c"
    goto label_101;
label_98:
#line 186 "sample/undocked/map.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-64));
#line 186 "sample/undocked/map.c"
    r2 = r10;
#line 186 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
#line 186 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
#line 186 "sample/undocked/map.c"
    r3 = IMMEDIATE(2);
#line 186 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[9].address(r1, r2, r3, r4, r5, context);
#line 186 "sample/undocked/map.c"
    r7 = r0;
#line 186 "sample/undocked/map.c"
    r5 = r7;
#line 186 "sample/undocked/map.c"
    r5 <<= (IMMEDIATE(32) & 63);
#line 186 "sample/undocked/map.c"
    r1 = r5;
#line 186 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
#line 186 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 186 "sample/undocked/map.c"
        goto label_102;
#line 186 "sample/undocked/map.c"
    }
#line 186 "sample/undocked/map.c"
    r1 = IMMEDIATE(25637);
#line 186 "sample/undocked/map.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-68));
#line 186 "sample/undocked/map.c"
    r1 = IMMEDIATE(543450478);
#line 186 "sample/undocked/map.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-72));
#line 186 "sample/undocked/map.c"
    r1 = (uint64_t)8247626271654175781;
#line 186 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-80));
#line 186 "sample/undocked/map.c"
    r1 = (uint64_t)2334102057442963576;
#line 186 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
#line 186 "sample/undocked/map.c"
    r1 = (uint64_t)7286934307705679465;
#line 186 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 186 "sample/undocked/map.c"
    r1 = (uint64_t)8390880602192683117;
#line 186 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 186 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755764168048;
#line 186 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 186 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
#line 186 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 186 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 186 "sample/undocked/map.c"
    WRITE_ONCE_8(r10, (uint8_t)r1, OFFSET(-66));
#line 186 "sample/undocked/map.c"
    READ_ONCE_32(r3, r10, OFFSET(-64));
#line 186 "sample/undocked/map.c"
    goto label_100;
label_99:
#line 186 "sample/undocked/map.c"
    r1 = IMMEDIATE(25637);
#line 182 "sample/undocked/map.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-68));
#line 182 "sample/undocked/map.c"
    r1 = IMMEDIATE(543450478);
#line 182 "sample/undocked/map.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-72));
#line 182 "sample/undocked/map.c"
    r1 = (uint64_t)8247626271654175781;
#line 182 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-80));
#line 182 "sample/undocked/map.c"
    r1 = (uint64_t)2334102057442963576;
#line 182 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
#line 182 "sample/undocked/map.c"
    r1 = (uint64_t)7286934307705679465;
#line 182 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 182 "sample/undocked/map.c"
    r1 = (uint64_t)8390880602192683117;
#line 182 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 182 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755764168048;
#line 182 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 182 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
#line 182 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 182 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 182 "sample/undocked/map.c"
    WRITE_ONCE_8(r10, (uint8_t)r1, OFFSET(-66));
#line 182 "sample/undocked/map.c"
    READ_ONCE_32(r3, r10, OFFSET(-4));
label_100:
#line 182 "sample/undocked/map.c"
    r5 = (int64_t)r5 >> (uint32_t)(IMMEDIATE(32) & 63);
#line 182 "sample/undocked/map.c"
    r1 = r10;
#line 182 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
#line 182 "sample/undocked/map.c"
    r2 = IMMEDIATE(55);
#line 182 "sample/undocked/map.c"
    r4 = IMMEDIATE(0);
label_101:
#line 182 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[10].address(r1, r2, r3, r4, r5, context);
#line 182 "sample/undocked/map.c"
    goto label_90;
label_102:
#line 182 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 188 "sample/undocked/map.c"
    WRITE_ONCE_32(r10, (uint32_t)r1, OFFSET(-64));
#line 188 "sample/undocked/map.c"
    r2 = r10;
#line 188 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
#line 188 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
#line 188 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[6].address(r1, r2, r3, r4, r5, context);
#line 188 "sample/undocked/map.c"
    r7 = r0;
#line 188 "sample/undocked/map.c"
    r4 = r7;
#line 188 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
#line 188 "sample/undocked/map.c"
    r1 = r4;
#line 188 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
#line 188 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 188 "sample/undocked/map.c"
        goto label_104;
#line 188 "sample/undocked/map.c"
    }
#line 188 "sample/undocked/map.c"
    r1 = IMMEDIATE(100);
#line 188 "sample/undocked/map.c"
    WRITE_ONCE_16(r10, (uint16_t)r1, OFFSET(-72));
#line 188 "sample/undocked/map.c"
    r1 = (uint64_t)2675248565465544052;
#line 188 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-80));
#line 188 "sample/undocked/map.c"
    r1 = (uint64_t)7309940759667438700;
#line 188 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
#line 188 "sample/undocked/map.c"
    r1 = (uint64_t)8463219665603620457;
#line 188 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 188 "sample/undocked/map.c"
    r1 = (uint64_t)8386658464824631405;
#line 188 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 188 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755813578096;
#line 188 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 188 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
#line 188 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 188 "sample/undocked/map.c"
    r4 = (int64_t)r4 >> (uint32_t)(IMMEDIATE(32) & 63);
#line 188 "sample/undocked/map.c"
    r1 = r10;
#line 188 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
#line 188 "sample/undocked/map.c"
    r2 = IMMEDIATE(50);
label_103:
#line 188 "sample/undocked/map.c"
    r3 = IMMEDIATE(0);
#line 188 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[7].address(r1, r2, r3, r4, r5, context);
#line 188 "sample/undocked/map.c"
    goto label_90;
label_104:
#line 188 "sample/undocked/map.c"
    READ_ONCE_32(r3, r10, OFFSET(-64));
#line 188 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(10)) {
#line 188 "sample/undocked/map.c"
        goto label_105;
#line 188 "sample/undocked/map.c"
    }
#line 188 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 188 "sample/undocked/map.c"
    WRITE_ONCE_8(r10, (uint8_t)r1, OFFSET(-80));
#line 188 "sample/undocked/map.c"
    r1 = (uint64_t)7216209606537213027;
#line 188 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
#line 188 "sample/undocked/map.c"
    r1 = (uint64_t)7309474570952779040;
#line 188 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 188 "sample/undocked/map.c"
    r1 = (uint64_t)7958552634295722093;
#line 188 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 188 "sample/undocked/map.c"
    r1 = (uint64_t)7308327755813578096;
#line 188 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 188 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
#line 188 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 188 "sample/undocked/map.c"
    r1 = r10;
#line 188 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
#line 188 "sample/undocked/map.c"
    r2 = IMMEDIATE(41);
#line 188 "sample/undocked/map.c"
    r4 = IMMEDIATE(10);
#line 188 "sample/undocked/map.c"
    goto label_89;
label_105:
#line 188 "sample/undocked/map.c"
    r6 = IMMEDIATE(0);
#line 192 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r6, OFFSET(-64));
#line 192 "sample/undocked/map.c"
    READ_ONCE_64(r1, r10, OFFSET(-64));
#line 192 "sample/undocked/map.c"
    if (r1 > IMMEDIATE(9)) {
#line 192 "sample/undocked/map.c"
        goto label_107;
#line 192 "sample/undocked/map.c"
    }
#line 192 "sample/undocked/map.c"
    r8 = IMMEDIATE(10);
#line 192 "sample/undocked/map.c"
    goto label_108;
label_106:
#line 192 "sample/undocked/map.c"
    READ_ONCE_64(r1, r10, OFFSET(-64));
#line 192 "sample/undocked/map.c"
    r1 += IMMEDIATE(1);
#line 192 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-64));
#line 192 "sample/undocked/map.c"
    READ_ONCE_64(r1, r10, OFFSET(-64));
#line 192 "sample/undocked/map.c"
    if (r8 > r1) {
#line 192 "sample/undocked/map.c"
        goto label_108;
#line 192 "sample/undocked/map.c"
    }
label_107:
#line 196 "sample/undocked/map.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-64));
#line 196 "sample/undocked/map.c"
    r2 = r10;
#line 196 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
#line 196 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
#line 196 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[6].address(r1, r2, r3, r4, r5, context);
#line 196 "sample/undocked/map.c"
    r7 = r0;
#line 196 "sample/undocked/map.c"
    r4 = r7;
#line 196 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
#line 196 "sample/undocked/map.c"
    r1 = r4;
#line 196 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
#line 196 "sample/undocked/map.c"
    r2 = (uint64_t)4294967289;
#line 196 "sample/undocked/map.c"
    if (r1 == r2) {
#line 196 "sample/undocked/map.c"
        goto label_110;
#line 196 "sample/undocked/map.c"
    }
#line 196 "sample/undocked/map.c"
    goto label_60;
label_108:
#line 193 "sample/undocked/map.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-4));
#line 193 "sample/undocked/map.c"
    r2 = r10;
#line 193 "sample/undocked/map.c"
    r2 += IMMEDIATE(-4);
#line 193 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
#line 193 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[8].address(r1, r2, r3, r4, r5, context);
#line 193 "sample/undocked/map.c"
    r7 = r0;
#line 193 "sample/undocked/map.c"
    r4 = r7;
#line 193 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
#line 193 "sample/undocked/map.c"
    r1 = r4;
#line 193 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
#line 193 "sample/undocked/map.c"
    if (r1 == IMMEDIATE(0)) {
#line 193 "sample/undocked/map.c"
        goto label_109;
#line 193 "sample/undocked/map.c"
    }
#line 193 "sample/undocked/map.c"
    goto label_111;
label_109:
#line 193 "sample/undocked/map.c"
    READ_ONCE_64(r1, r10, OFFSET(-64));
#line 193 "sample/undocked/map.c"
    r2 = IMMEDIATE(10);
#line 193 "sample/undocked/map.c"
    r2 -= r1;
#line 193 "sample/undocked/map.c"
    READ_ONCE_32(r3, r10, OFFSET(-4));
#line 193 "sample/undocked/map.c"
    if (r2 == r3) {
#line 193 "sample/undocked/map.c"
        goto label_106;
#line 193 "sample/undocked/map.c"
    }
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)28188318775535988;
#line 193 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)7162254444797649957;
#line 193 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)2336931105441411616;
#line 193 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
#line 193 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
#line 193 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 193 "sample/undocked/map.c"
    READ_ONCE_64(r1, r10, OFFSET(-64));
#line 193 "sample/undocked/map.c"
    r4 = IMMEDIATE(10);
#line 193 "sample/undocked/map.c"
    r4 -= r1;
#line 193 "sample/undocked/map.c"
    r1 = r10;
#line 193 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
#line 193 "sample/undocked/map.c"
    r2 = IMMEDIATE(40);
#line 193 "sample/undocked/map.c"
    goto label_89;
label_110:
#line 196 "sample/undocked/map.c"
    READ_ONCE_32(r3, r10, OFFSET(-64));
#line 196 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(0)) {
#line 196 "sample/undocked/map.c"
        goto label_112;
#line 196 "sample/undocked/map.c"
    }
#line 196 "sample/undocked/map.c"
    goto label_87;
label_111:
#line 196 "sample/undocked/map.c"
    r1 = (uint64_t)7216209593501643381;
#line 193 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-80));
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)8387235364492091508;
#line 193 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-88));
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)7815279607914981230;
#line 193 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-96));
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)7598807758610654496;
#line 193 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-104));
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)7882825905430622064;
#line 193 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-112));
#line 193 "sample/undocked/map.c"
    r1 = (uint64_t)6877103753374625890;
#line 193 "sample/undocked/map.c"
    WRITE_ONCE_64(r10, (uint64_t)r1, OFFSET(-120));
#line 193 "sample/undocked/map.c"
    r1 = IMMEDIATE(0);
#line 193 "sample/undocked/map.c"
    WRITE_ONCE_8(r10, (uint8_t)r1, OFFSET(-72));
#line 193 "sample/undocked/map.c"
    r4 = (int64_t)r4 >> (uint32_t)(IMMEDIATE(32) & 63);
#line 193 "sample/undocked/map.c"
    r1 = r10;
#line 193 "sample/undocked/map.c"
    r1 += IMMEDIATE(-120);
#line 193 "sample/undocked/map.c"
    r2 = IMMEDIATE(49);
#line 193 "sample/undocked/map.c"
    goto label_103;
label_112:
#line 193 "sample/undocked/map.c"
    r6 = IMMEDIATE(0);
#line 197 "sample/undocked/map.c"
    WRITE_ONCE_32(r10, (uint32_t)r6, OFFSET(-64));
#line 197 "sample/undocked/map.c"
    r2 = r10;
#line 197 "sample/undocked/map.c"
    r2 += IMMEDIATE(-64);
#line 197 "sample/undocked/map.c"
    r1 = POINTER(runtime_context->map_data[7].address);
#line 197 "sample/undocked/map.c"
    r0 = runtime_context->helper_data[8].address(r1, r2, r3, r4, r5, context);
#line 197 "sample/undocked/map.c"
    r7 = r0;
#line 197 "sample/undocked/map.c"
    r4 = r7;
#line 197 "sample/undocked/map.c"
    r4 <<= (IMMEDIATE(32) & 63);
#line 197 "sample/undocked/map.c"
    r1 = r4;
#line 197 "sample/undocked/map.c"
    r1 >>= (IMMEDIATE(32) & 63);
#line 197 "sample/undocked/map.c"
    r2 = (uint64_t)4294967289;
#line 197 "sample/undocked/map.c"
    if (r1 == r2) {
#line 197 "sample/undocked/map.c"
        goto label_113;
#line 197 "sample/undocked/map.c"
    }
#line 197 "sample/undocked/map.c"
    goto label_92;
label_113:
#line 197 "sample/undocked/map.c"
    READ_ONCE_32(r3, r10, OFFSET(-64));
#line 197 "sample/undocked/map.c"
    if (r3 == IMMEDIATE(0)) {
#line 197 "sample/undocked/map.c"
        goto label_8;
#line 197 "sample/undocked/map.c"
    }
#line 197 "sample/undocked/map.c"
    goto label_94;
#line 202 "sample/undocked/map.c"
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
        1766,
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

metadata_table_t map_metadata_table = {
    sizeof(metadata_table_t),
    _get_programs,
    _get_maps,
    _get_hash,
    _get_version,
    _get_map_initial_values,
    _get_global_variable_sections,
};
