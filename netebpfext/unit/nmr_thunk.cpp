// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "netebpfext_platform.h"
#include "nmr_thunk.h"

void
NmrProviderDetachClientComplete(_In_ HANDLE nmr_binding_handle)
{}

NTSTATUS
NmrDeregisterProvider(_In_ HANDLE nmr_provider_handle) { return STATUS_NO_MEMORY; }

NTSTATUS
NmrWaitForProviderDeregisterComplete(_In_ HANDLE nmr_provider_handle) { return STATUS_NO_MEMORY; }

NTSTATUS
NmrRegisterProvider(
    _In_ NPI_PROVIDER_CHARACTERISTICS* provider_characteristics,
    _In_opt_ __drv_aliasesMem void* provider_context,
    _Out_ HANDLE* nmr_provider_handle)
{
    return STATUS_NO_MEMORY;
}