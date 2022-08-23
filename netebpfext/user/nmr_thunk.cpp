// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <vector>
#include <unordered_map>

#include "netebpfext_platform.h"
#include "nmr_thunk.h"

typedef struct _NMR_REGISTRATION
{
    NPI_PROVIDER_CHARACTERISTICS provider_characteristics;
    void* provider_context;
} NMR_REGISTRATION;

size_t _nmr_next_handle = 1;
std::unordered_map<size_t, NMR_REGISTRATION> _nmr_registrations;

void
NmrProviderDetachClientComplete(_In_ HANDLE nmr_binding_handle)
{
    UNREFERENCED_PARAMETER(nmr_binding_handle);
}

NTSTATUS
NmrDeregisterProvider(_In_ HANDLE nmr_provider_handle)
{
    if (_nmr_registrations.erase((size_t)nmr_provider_handle) == 0) {
        return STATUS_INVALID_HANDLE;
    } else {
        return STATUS_SUCCESS;
    }
}

NTSTATUS
NmrWaitForProviderDeregisterComplete(_In_ HANDLE nmr_provider_handle)
{
    UNREFERENCED_PARAMETER(nmr_provider_handle);
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NmrRegisterProvider(
    _In_ NPI_PROVIDER_CHARACTERISTICS* provider_characteristics,
    _In_opt_ __drv_aliasesMem void* provider_context,
    _Out_ HANDLE* nmr_provider_handle)
{
    size_t handle = _nmr_next_handle++;
    _nmr_registrations.insert({handle, {*provider_characteristics, provider_context}});
    *nmr_provider_handle = reinterpret_cast<HANDLE>(handle);
    return STATUS_SUCCESS;
}