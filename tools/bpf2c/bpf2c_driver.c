// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <wdm.h>
#include <wsk.h>

#define BPF2C_DRIVER_CODE
#include "bpf2c.h"

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
RTL_QUERY_REGISTRY_ROUTINE static _bpf2c_query_registry_routine;

static NPI_MODULEID _bpf2c_module_id = {sizeof(_bpf2c_module_id), MIT_GUID, {0}};
static HANDLE _bpf2c_nmr_client_handle;
static HANDLE _bpf2c_nmr_provider_handle;
metadata_table_t ___META_DATA_TABLE___;

static NTSTATUS
_bpf2c_npi_client_attach_provider(
    HANDLE nmr_binding_handle, void* client_context, const NPI_REGISTRATION_INSTANCE* provider_registration_instance);

static NTSTATUS
_bpf2c_npi_client_detach_provider(void* ClientBindingContext);

static const NPI_CLIENT_CHARACTERISTICS _bpf2c_npi_client_characteristics = {
    0,                                  // Version
    sizeof(NPI_CLIENT_CHARACTERISTICS), // Length
    _bpf2c_npi_client_attach_provider,
    _bpf2c_npi_client_detach_provider,
    NULL,
    {0,                                 // Version
     sizeof(NPI_REGISTRATION_INSTANCE), // Length
     &bpf2c_npi_id,
     &_bpf2c_module_id,
     0,
     &___META_DATA_TABLE___}};

NTSTATUS
bpf2c_query_npi_module_id(
    PWSTR ValueName, ULONG ValueType, PVOID ValueData, ULONG ValueLength, PVOID Context, PVOID EntryContext)
{
    UNREFERENCED_PARAMETER(ValueName);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(EntryContext);

    if (ValueType != REG_BINARY) {
        return STATUS_INVALID_PARAMETER;
    }
    if (ValueLength != sizeof(_bpf2c_module_id.Guid)) {
        return STATUS_INVALID_PARAMETER;
    }

    memcpy(&_bpf2c_module_id.Guid, ValueData, ValueLength);
    return STATUS_SUCCESS;
}

NTSTATUS
DriverEntry(DRIVER_OBJECT* driver_object, UNICODE_STRING* registry_path)
{
    NTSTATUS status;
    wchar_t parameter[] = L"\\Parameters";
    wchar_t parameters_sub_key[512] = {0};
    RTL_QUERY_REGISTRY_TABLE query_table[2] = {
        {
            bpf2c_query_npi_module_id,   // Query routine
            RTL_QUERY_REGISTRY_REQUIRED, // Flags
            L"NpiModuleId",              // Name
            NULL,                        // Entry contet
            REG_NONE,                    // Default type
            NULL,                        // Default data
            0,                           // Default length
        },
        {0}};
    memcpy(parameters_sub_key, registry_path->Buffer, registry_path->Length);
    wcsncat(parameters_sub_key, parameter, 512 - wcslen(parameters_sub_key));

    status = RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, parameters_sub_key, query_table, NULL, NULL);
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
DriverUnload(struct _DRIVER_OBJECT* DriverObject)
{
    NTSTATUS status = NmrDeregisterClient(_bpf2c_nmr_client_handle);
    if (status == STATUS_PENDING) {
        NmrWaitForClientDeregisterComplete(_bpf2c_nmr_client_handle);
    }
    UNREFERENCED_PARAMETER(DriverObject);
}

NTSTATUS
_bpf2c_npi_client_attach_provider(
    HANDLE nmr_binding_handle, void* client_context, const NPI_REGISTRATION_INSTANCE* provider_registration_instance)
{
    UNREFERENCED_PARAMETER(client_context);
    UNREFERENCED_PARAMETER(provider_registration_instance);
    if (_bpf2c_nmr_provider_handle != NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    _bpf2c_nmr_provider_handle = nmr_binding_handle;
    return STATUS_SUCCESS;
}

NTSTATUS
_bpf2c_npi_client_detach_provider(void* ClientBindingContext)
{
    _bpf2c_nmr_provider_handle = NULL;
    UNREFERENCED_PARAMETER(ClientBindingContext);
    return STATUS_SUCCESS;
}
