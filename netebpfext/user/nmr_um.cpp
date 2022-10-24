// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "netebpfext_platform.h"
#include "nmr_impl.h"

// TODO(Issue #1134): ebpf_extension_user.c doesn't implement provider unload correctly.
// Move this code over to platform\user so that we can reduce the amount of code that
// is not hit by user mode tests.

static nmr_t _nmr;

NTSTATUS
NmrRegisterProvider(
    _In_ const NPI_PROVIDER_CHARACTERISTICS* provider_characteristics,
    _In_opt_ __drv_aliasesMem void* provider_context,
    _Out_ HANDLE* nmr_provider_handle)
{
    try {
        *nmr_provider_handle = _nmr.register_provider(*provider_characteristics, provider_context);
        return STATUS_SUCCESS;
    } catch (std::bad_alloc) {
        return STATUS_NO_MEMORY;
    }
}

NTSTATUS
NmrDeregisterProvider(_In_ HANDLE nmr_provider_handle)
{
    try {
        if (_nmr.deregister_provider(nmr_provider_handle)) {
            return STATUS_PENDING;
        } else {
            return STATUS_SUCCESS;
        }
    } catch (std::bad_alloc) {
        return STATUS_NO_MEMORY;
    }
}

void
NmrProviderDetachClientComplete(_In_ HANDLE nmr_binding_handle)
{
    try {
        _nmr.binding_detach_client_complete(nmr_binding_handle);
    } catch (std::bad_alloc) {
        return;
    }
}

NTSTATUS
NmrWaitForProviderDeregisterComplete(_In_ HANDLE nmr_provider_handle)
{
    try {
        _nmr.wait_for_deregister_provider(nmr_provider_handle);
        return STATUS_SUCCESS;
    } catch (std::bad_alloc) {
        return STATUS_NO_MEMORY;
    }
}

NTSTATUS
NmrRegisterClient(
    _In_ const NPI_CLIENT_CHARACTERISTICS* client_characteristics,
    _In_opt_ __drv_aliasesMem void* client_context,
    _Out_ HANDLE* nmr_client_handle)
{
    try {
        *nmr_client_handle = _nmr.register_client(*client_characteristics, client_context);
        return STATUS_SUCCESS;
    } catch (std::bad_alloc) {
        return STATUS_NO_MEMORY;
    }
}

NTSTATUS
NmrDeregisterClient(_In_ HANDLE nmr_client_handle)
{
    try {
        if (_nmr.deregister_client(nmr_client_handle)) {
            return STATUS_PENDING;
        } else {
            return STATUS_SUCCESS;
        }
    } catch (std::bad_alloc) {
        return STATUS_NO_MEMORY;
    }
}

void
NmrClientDetachProviderComplete(_In_ HANDLE nmr_binding_handle)
{
    try {
        _nmr.binding_detach_provider_complete(nmr_binding_handle);
    } catch (std::bad_alloc) {
        return;
    }
}

NTSTATUS
NmrWaitForClientDeregisterComplete(_In_ HANDLE nmr_client_handle)
{
    try {
        _nmr.wait_for_deregister_client(nmr_client_handle);
        return STATUS_SUCCESS;
    } catch (std::bad_alloc) {
        return STATUS_NO_MEMORY;
    }
}

NTSTATUS
NmrClientAttachProvider(
    _In_ HANDLE nmr_binding_handle,
    _In_ __drv_aliasesMem void* client_binding_context,
    _In_ const void* client_dispatch,
    _Out_ void** provider_binding_context,
    _Out_ const void** provider_dispatch)
{
    try {
        return _nmr.client_attach_provider(
            nmr_binding_handle,
            client_binding_context,
            client_dispatch,
            (const void**)provider_binding_context,
            provider_dispatch);
    } catch (std::bad_alloc) {
        return STATUS_NO_MEMORY;
    }
}