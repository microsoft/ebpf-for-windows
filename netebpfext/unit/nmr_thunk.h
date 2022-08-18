// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

typedef struct _NPI_REGISTRATION_INSTANCE
{
    uint16_t Size;
    PNPIID NpiId;
    PNPI_MODULEID ModuleId;
    unsigned long Number;
    const void* NpiSpecificCharacteristics;
} NPI_REGISTRATION_INSTANCE, *PNPI_REGISTRATION_INSTANCE;

typedef NTSTATUS(NPI_PROVIDER_ATTACH_CLIENT_FN)(
    _In_ HANDLE nmr_binding_handle,
    _In_ void* provider_context,
    _In_ const NPI_REGISTRATION_INSTANCE* ClientRegistrationInstance,
    _In_ void* ClientBindingContext,
    _In_ const void* ClientDispatch,
    _Outptr_ void** ProviderBindingContext,
    _Outptr_result_maybenull_ const void** ProviderDispatch);
typedef NPI_PROVIDER_ATTACH_CLIENT_FN* PNPI_PROVIDER_ATTACH_CLIENT_FN;

typedef NTSTATUS(NPI_PROVIDER_DETACH_CLIENT_FN)(_In_ void* ProviderBindingContext);
typedef NPI_PROVIDER_DETACH_CLIENT_FN* PNPI_PROVIDER_DETACH_CLIENT_FN;

typedef void(NPI_PROVIDER_CLEANUP_BINDING_CONTEXT_FN)(_In_ void* ProviderBindingContext);
typedef NPI_PROVIDER_CLEANUP_BINDING_CONTEXT_FN* PNPI_PROVIDER_CLEANUP_BINDING_CONTEXT_FN;

typedef struct _NPI_PROVIDER_CHARACTERISTICS
{
    uint16_t Version;
    uint16_t Length;
    PNPI_PROVIDER_ATTACH_CLIENT_FN ProviderAttachClient;
    PNPI_PROVIDER_DETACH_CLIENT_FN ProviderDetachClient;
    PNPI_PROVIDER_CLEANUP_BINDING_CONTEXT_FN ProviderCleanupBindingContext;
    NPI_REGISTRATION_INSTANCE ProviderRegistrationInstance;
} NPI_PROVIDER_CHARACTERISTICS;

typedef GUID NPIID;
typedef const NPIID* PNPIID;

void
NmrProviderDetachClientComplete(_In_ HANDLE nmr_binding_handle);

NTSTATUS
NmrDeregisterProvider(_In_ HANDLE nmr_provider_handle);

NTSTATUS
NmrWaitForProviderDeregisterComplete(_In_ HANDLE nmr_provider_handle);

NTSTATUS
NmrRegisterProvider(
    _In_ NPI_PROVIDER_CHARACTERISTICS* provider_characteristics,
    _In_opt_ __drv_aliasesMem void* provider_context,
    _Out_ HANDLE* nmr_provider_handle);
