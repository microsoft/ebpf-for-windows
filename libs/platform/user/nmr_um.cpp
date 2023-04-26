// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_fault_injection.h"
#include "nmr_impl.h"

nmr_t _nmr::singleton;

NTSTATUS
NmrRegisterProvider(
    _In_ const NPI_PROVIDER_CHARACTERISTICS* provider_characteristics,
    _In_opt_ __drv_aliasesMem void* provider_context,
    _Out_ HANDLE* nmr_provider_handle)
{
    if (ebpf_fault_injection_inject_fault()) {
        return STATUS_NO_MEMORY;
    }

    try {
        *nmr_provider_handle = nmr_t::get().register_provider(*provider_characteristics, provider_context);
        return STATUS_SUCCESS;
    } catch (std::bad_alloc) {
        return STATUS_NO_MEMORY;
    }
}

NTSTATUS
NmrDeregisterProvider(_In_ HANDLE nmr_provider_handle)
{
    try {
        if (_nmr::get().deregister_provider(nmr_provider_handle)) {
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
        _nmr::get().binding_detach_client_complete(nmr_binding_handle);
    } catch (std::bad_alloc) {
        return;
    }
}

NTSTATUS
NmrWaitForProviderDeregisterComplete(_In_ HANDLE nmr_provider_handle)
{
    try {
        _nmr::get().wait_for_deregister_provider(nmr_provider_handle);
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
    if (ebpf_fault_injection_inject_fault()) {
        return STATUS_NO_MEMORY;
    }

    try {
        *nmr_client_handle = _nmr::get().register_client(*client_characteristics, client_context);
        return STATUS_SUCCESS;
    } catch (std::bad_alloc) {
        return STATUS_NO_MEMORY;
    }
}

NTSTATUS
NmrDeregisterClient(_In_ HANDLE nmr_client_handle)
{
    try {
        if (_nmr::get().deregister_client(nmr_client_handle)) {
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
        _nmr::get().binding_detach_provider_complete(nmr_binding_handle);
    } catch (std::bad_alloc) {
        return;
    }
}

NTSTATUS
NmrWaitForClientDeregisterComplete(_In_ HANDLE nmr_client_handle)
{
    try {
        _nmr::get().wait_for_deregister_client(nmr_client_handle);
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
    if (ebpf_fault_injection_inject_fault()) {
        return STATUS_NO_MEMORY;
    }

    try {
        return _nmr::get().client_attach_provider(
            nmr_binding_handle,
            client_binding_context,
            client_dispatch,
            (const void**)provider_binding_context,
            provider_dispatch);
    } catch (std::bad_alloc) {
        return STATUS_NO_MEMORY;
    }
}
