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
    _In_ const NPI_REGISTRATION_INSTANCE* client_registration_instance,
    _In_ void* client_binding_context,
    _In_ const void* client_dispatch,
    _Outptr_ void** provider_binding_context,
    _Outptr_result_maybenull_ const void** provider_dispatch);
typedef NPI_PROVIDER_ATTACH_CLIENT_FN* PNPI_PROVIDER_ATTACH_CLIENT_FN;

typedef NTSTATUS(NPI_PROVIDER_DETACH_CLIENT_FN)(_In_ void* provider_binding_context);
typedef NPI_PROVIDER_DETACH_CLIENT_FN* PNPI_PROVIDER_DETACH_CLIENT_FN;

typedef void(NPI_PROVIDER_CLEANUP_BINDING_CONTEXT_FN)(_In_ void* provider_binding_context);
typedef NPI_PROVIDER_CLEANUP_BINDING_CONTEXT_FN* PNPI_PROVIDER_CLEANUP_BINDING_CONTEXT_FN;

typedef NTSTATUS(NTAPI NPI_CLIENT_ATTACH_PROVIDER_FN)(
    _In_ HANDLE nmr_binding_handle,
    _In_ PVOID client_context,
    _In_ PNPI_REGISTRATION_INSTANCE provider_registration_instance);
typedef NPI_CLIENT_ATTACH_PROVIDER_FN* PNPI_CLIENT_ATTACH_PROVIDER_FN;

typedef NTSTATUS(NTAPI NPI_CLIENT_DETACH_PROVIDER_FN)(_In_ PVOID client_binding_context);
typedef NPI_CLIENT_DETACH_PROVIDER_FN* PNPI_CLIENT_DETACH_PROVIDER_FN;

typedef VOID(NTAPI NPI_CLIENT_CLEANUP_BINDING_CONTEXT_FN)(_In_ PVOID client_binding_context);
typedef NPI_CLIENT_CLEANUP_BINDING_CONTEXT_FN* PNPI_CLIENT_CLEANUP_BINDING_CONTEXT_FN;

typedef struct _NPI_PROVIDER_CHARACTERISTICS
{
    uint16_t Version;
    uint16_t Length;
    PNPI_PROVIDER_ATTACH_CLIENT_FN ProviderAttachClient;
    PNPI_PROVIDER_DETACH_CLIENT_FN ProviderDetachClient;
    PNPI_PROVIDER_CLEANUP_BINDING_CONTEXT_FN ProviderCleanupBindingContext;
    NPI_REGISTRATION_INSTANCE ProviderRegistrationInstance;
} NPI_PROVIDER_CHARACTERISTICS;

typedef struct _NPI_CLIENT_CHARACTERISTICS
{
    USHORT Version;
    USHORT Length;
    PNPI_CLIENT_ATTACH_PROVIDER_FN ClientAttachProvider;
    PNPI_CLIENT_DETACH_PROVIDER_FN ClientDetachProvider;
    PNPI_CLIENT_CLEANUP_BINDING_CONTEXT_FN ClientCleanupBindingContext;
    NPI_REGISTRATION_INSTANCE ClientRegistrationInstance;
} NPI_CLIENT_CHARACTERISTICS;

typedef GUID NPIID;
typedef const NPIID* PNPIID;

NTSTATUS
NmrRegisterProvider(
    _In_ NPI_PROVIDER_CHARACTERISTICS* provider_characteristics,
    _In_opt_ __drv_aliasesMem void* provider_context,
    _Out_ HANDLE* nmr_provider_handle);

NTSTATUS
NmrDeregisterProvider(_In_ HANDLE nmr_provider_handle);

NTSTATUS
NmrWaitForProviderDeregisterComplete(_In_ HANDLE nmr_provider_handle);

void
NmrProviderDetachClientComplete(_In_ HANDLE nmr_binding_handle);

NTSTATUS
NmrRegisterClient(
    _In_ NPI_CLIENT_CHARACTERISTICS* client_characteristics,
    _In_ void* client_context,
    _Out_ HANDLE* nmr_client_handle);

NTSTATUS
NmrDeregisterClient(_In_ HANDLE nmr_client_handle);

NTSTATUS
NmrWaitForClientDeregisterComplete(_In_ HANDLE nmr_client_handle);

NTSTATUS
NmrClientAttachProvider(
    _In_ HANDLE NmrBindingHandle,
    _In_ __drv_aliasesMem PVOID ClientBindingContext,
    _In_ const void* ClientDispatch,
    _Out_ void** ProviderBindingContext,
    _Out_ const void** ProviderDispatch);