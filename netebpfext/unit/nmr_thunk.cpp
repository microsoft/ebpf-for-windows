// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "netebpfext_platform.h"
#include "nmr_thunk.h"

void
NmrProviderDetachClientComplete(_In_ HANDLE NmrBindingHandle)
{}

NTSTATUS
NmrDeregisterProvider(_In_ HANDLE NmrProviderHandle) { return STATUS_NO_MEMORY; }

NTSTATUS
NmrWaitForProviderDeregisterComplete(_In_ HANDLE NmrProviderHandle) { return STATUS_NO_MEMORY; }

NTSTATUS
NmrRegisterProvider(
    _In_ NPI_PROVIDER_CHARACTERISTICS* ProviderCharacteristics,
    _In_opt_ __drv_aliasesMem void* ProviderContext,
    _Out_ PHANDLE NmrProviderHandle)
{
    return STATUS_NO_MEMORY;
}