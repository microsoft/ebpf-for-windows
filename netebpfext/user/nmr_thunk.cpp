// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "netebpfext_platform.h"
#include "nmr_thunk.h"

void
NmrProviderDetachClientComplete(_In_ HANDLE nmr_binding_handle)
{
    UNREFERENCED_PARAMETER(nmr_binding_handle);
}

NTSTATUS
NmrDeregisterProvider(_In_ HANDLE nmr_provider_handle)
{
    UNREFERENCED_PARAMETER(nmr_provider_handle);
    return STATUS_SUCCESS;
}

NTSTATUS
NmrWaitForProviderDeregisterComplete(_In_ HANDLE nmr_provider_handle)
{
    UNREFERENCED_PARAMETER(nmr_provider_handle);
    return STATUS_SUCCESS;
}

NTSTATUS
NmrRegisterProvider(
    _In_ NPI_PROVIDER_CHARACTERISTICS* provider_characteristics,
    _In_opt_ __drv_aliasesMem void* provider_context,
    _Out_ HANDLE* nmr_provider_handle)
{
    UNREFERENCED_PARAMETER(provider_characteristics);
    UNREFERENCED_PARAMETER(provider_context);
    UNREFERENCED_PARAMETER(nmr_provider_handle);
    return STATUS_NO_MEMORY;
}