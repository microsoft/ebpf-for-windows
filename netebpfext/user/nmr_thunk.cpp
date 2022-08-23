// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <condition_variable>
#include <mutex>
#include <vector>
#include <map>

#include "netebpfext_platform.h"
#include "nmr_thunk.h"

class _waitable_ref_count
{
  public:
    _waitable_ref_count() = default;
    ~_waitable_ref_count() = default;

    void
    add_ref()
    {
        std::unique_lock l(lock);
        count++;
        rundown.notify_all();
    }
    void
    release_ref()
    {
        std::unique_lock l(lock);
        count--;
        rundown.notify_all();
    }
    void
    wait()
    {
        auto& local_count = this->count;
        std::unique_lock l(lock);
        rundown.wait(l, [&local_count]() { return local_count == 0; });
    }
    bool
    rundown_complete()
    {
        std::unique_lock l(lock);
        return count == 0;
    }

  private:
    size_t count = 0;
    std::condition_variable rundown;
    std::mutex lock;
};

typedef struct _NMR_PROVIDER_REGISTRATION
{
    NPI_PROVIDER_CHARACTERISTICS characteristics;
    void* context;
    _waitable_ref_count ref_count;
} NMR_PROVIDER_REGISTRATION;

typedef struct _NMR_CLIENT_REGISTRATION
{
    NPI_CLIENT_CHARACTERISTICS characteristics;
    void* context;
    _waitable_ref_count ref_count;
} NMR_CLIENT_REGISTRATION;

typedef struct _NMR_BINDING
{
    HANDLE provider_handle;
    HANDLE client_handle;
    bool detach_pending;
    void* client_binding_context;
    const void* client_dispatch;
    void* provider_binding_context;
    const void* provider_dispatch;
} NMR_BINDING;

static size_t _nmr_next_handle = 1;
static std::map<HANDLE, NMR_PROVIDER_REGISTRATION> _nmr_provider_registrations;
static std::map<HANDLE, NMR_CLIENT_REGISTRATION> _nmr_client_registrations;
static std::map<std::tuple<HANDLE, HANDLE>, std::unique_ptr<NMR_BINDING>> _nmr_bindings;

static void
_delete_binding(HANDLE client_handle, HANDLE provider_handle)
{
    NTSTATUS status;
    bool pending = false;

    auto iter = _nmr_bindings.find({client_handle, provider_handle});
    ebpf_assert(iter != _nmr_bindings.end());

    // Notify client
    auto& client = _nmr_client_registrations[client_handle];
    status = client.characteristics.ClientDetachProvider(iter->second->client_binding_context);
    if (status == STATUS_SUCCESS) {
        client.ref_count.release_ref();
    } else if (status == STATUS_PENDING) {
        pending = true;
    }

    // Notify provider
    auto& provider = _nmr_provider_registrations[provider_handle];
    status = provider.characteristics.ProviderDetachClient(iter->second->provider_binding_context);
    if (status == STATUS_SUCCESS) {
        provider.ref_count.release_ref();
    } else if (status == STATUS_PENDING) {
        ebpf_assert(!pending);
        pending = true;
    }

    if (pending) {
        iter->second->detach_pending = true;
    } else {
        provider.characteristics.ProviderCleanupBindingContext(iter->second->provider_binding_context);
        client.characteristics.ClientCleanupBindingContext(iter->second->client_binding_context);
        _nmr_bindings.erase(iter);
    }
}

static void
_add_binding(HANDLE client_handle, HANDLE provider_handle)
{
    NTSTATUS client_status;

    auto& binding = _nmr_bindings[{client_handle, provider_handle}];
    auto& client = _nmr_client_registrations[client_handle];
    auto& provider = _nmr_provider_registrations[provider_handle];

    binding = std::make_unique<NMR_BINDING>();
    binding->client_handle = client_handle;
    binding->provider_handle = provider_handle;

    // During this callout, the client will callback into the NMR to set dispatch tables etc.
    client_status = client.characteristics.ClientAttachProvider(
        binding.get(), client.context, &provider.characteristics.ProviderRegistrationInstance);

    if (!NT_SUCCESS(client_status)) {
        provider.characteristics.ProviderCleanupBindingContext(binding->provider_binding_context);
        _nmr_bindings.erase({client_handle, provider_handle});
        return;
    } else {
        provider.ref_count.add_ref();
        client.ref_count.add_ref();
    }
}

NTSTATUS
NmrRegisterProvider(
    _In_ NPI_PROVIDER_CHARACTERISTICS* provider_characteristics,
    _In_opt_ __drv_aliasesMem void* provider_context,
    _Out_ HANDLE* nmr_provider_handle)
{
    HANDLE handle = reinterpret_cast<HANDLE>(_nmr_next_handle++);
    auto& provider = _nmr_provider_registrations[handle];
    provider.characteristics = *provider_characteristics;
    provider.context = provider_context;
    *nmr_provider_handle = reinterpret_cast<HANDLE>(handle);

    // Add any bindings for existing clients
    for (const auto& [client_handle, client] : _nmr_client_registrations) {
        if (client.characteristics.ClientRegistrationInstance.NpiId ==
            provider.characteristics.ProviderRegistrationInstance.NpiId) {
            _add_binding(client_handle, handle);
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS
NmrDeregisterProvider(_In_ HANDLE nmr_provider_handle)
{
    std::vector<HANDLE> clients_to_detach;
    auto iter = _nmr_provider_registrations.find(nmr_provider_handle);
    ebpf_assert(iter != _nmr_provider_registrations.end());
    auto& provider = iter->second;

    for (auto& [key, binding] : _nmr_bindings) {
        if (binding->provider_handle == nmr_provider_handle) {
            clients_to_detach.push_back(binding->client_handle);
        }
    }

    for (auto& client : clients_to_detach) {
        _delete_binding(client, nmr_provider_handle);
    }

    if (provider.ref_count.rundown_complete()) {
        _nmr_provider_registrations.erase(iter);
        return STATUS_SUCCESS;
    } else {
        return STATUS_PENDING;
    }
}

void
NmrProviderDetachClientComplete(_In_ HANDLE nmr_binding_handle)
{
    auto binding = reinterpret_cast<NMR_BINDING*>(nmr_binding_handle);
    auto& client = _nmr_client_registrations[binding->client_handle];
    auto& provider = _nmr_provider_registrations[binding->provider_handle];

    ebpf_assert(binding->detach_pending);

    // Notify the client that the detach is complete.
    client.ref_count.release_ref();

    provider.characteristics.ProviderCleanupBindingContext(binding->provider_binding_context);
    client.characteristics.ClientCleanupBindingContext(binding->client_binding_context);

    _nmr_bindings.erase({binding->client_handle, binding->provider_handle});
}

NTSTATUS
NmrWaitForProviderDeregisterComplete(_In_ HANDLE nmr_provider_handle)
{
    auto iter = _nmr_provider_registrations.find(nmr_provider_handle);
    ebpf_assert(iter != _nmr_provider_registrations.end());
    auto& provider = iter->second;

    provider.ref_count.wait();

    return STATUS_SUCCESS;
}

NTSTATUS
NmrRegisterClient(
    _In_ NPI_CLIENT_CHARACTERISTICS* client_characteristics, _In_ void* client_context, _Out_ HANDLE* nmr_client_handle)
{
    HANDLE handle = reinterpret_cast<HANDLE>(_nmr_next_handle++);
    auto& client = _nmr_client_registrations[handle];
    client.characteristics = *client_characteristics;
    client.context = client_context;
    *nmr_client_handle = reinterpret_cast<HANDLE>(handle);

    // Add any bindings for existing clients
    for (const auto& [provider_handle, provider] : _nmr_provider_registrations) {
        if (provider.characteristics.ProviderRegistrationInstance.NpiId ==
            client.characteristics.ClientRegistrationInstance.NpiId) {
            _add_binding(handle, provider_handle);
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS
NmrDeregisterClient(_In_ HANDLE nmr_client_handle)
{
    std::vector<HANDLE> providers_to_detach;
    auto iter = _nmr_client_registrations.find(nmr_client_handle);
    ebpf_assert(iter != _nmr_client_registrations.end());
    auto& client = iter->second;

    for (auto& [key, binding] : _nmr_bindings) {
        if (binding->client_handle == nmr_client_handle) {
            providers_to_detach.push_back(binding->provider_handle);
        }
    }

    for (auto& provider : providers_to_detach) {
        _delete_binding(nmr_client_handle, provider);
    }

    if (client.ref_count.rundown_complete()) {
        _nmr_client_registrations.erase(iter);
        return STATUS_SUCCESS;
    } else {
        return STATUS_PENDING;
    }
}

void
NmrClientDetachProviderComplete(_In_ HANDLE nmr_binding_handle)
{
    auto binding = reinterpret_cast<NMR_BINDING*>(nmr_binding_handle);
    auto& client = _nmr_client_registrations[binding->client_handle];
    auto& provider = _nmr_provider_registrations[binding->provider_handle];

    ebpf_assert(binding->detach_pending);

    // Notify the provider that the detach is complete.
    provider.ref_count.release_ref();

    provider.characteristics.ProviderCleanupBindingContext(binding->provider_binding_context);
    client.characteristics.ClientCleanupBindingContext(binding->client_binding_context);

    _nmr_bindings.erase({binding->client_handle, binding->provider_handle});
}

NTSTATUS
NmrWaitForClientDeregisterComplete(_In_ HANDLE nmr_client_handle)
{
    auto iter = _nmr_client_registrations.find(nmr_client_handle);
    ebpf_assert(iter != _nmr_client_registrations.end());
    auto& client = iter->second;

    client.ref_count.wait();

    return STATUS_SUCCESS;
}

NTSTATUS
NmrClientAttachProvider(
    _In_ HANDLE nmr_binding_handle,
    _In_ __drv_aliasesMem void* client_binding_context,
    _In_ const void* client_dispatch,
    _Out_ void** provider_binding_context,
    _Out_ const void** provider_dispatch)
{
    NTSTATUS status;
    auto binding = reinterpret_cast<NMR_BINDING*>(nmr_binding_handle);
    auto& client = _nmr_client_registrations[binding->client_handle];
    auto& provider = _nmr_provider_registrations[binding->provider_handle];

    binding->client_binding_context = client_binding_context;
    binding->client_dispatch = client_dispatch;

    status = provider.characteristics.ProviderAttachClient(
        nmr_binding_handle,
        provider.context,
        &client.characteristics.ClientRegistrationInstance,
        binding->client_binding_context,
        binding->client_dispatch,
        &binding->provider_binding_context,
        &binding->provider_dispatch);

    if (!NT_SUCCESS(status)) {
        return status;
    }
    *provider_binding_context = binding->provider_binding_context;
    *provider_dispatch = binding->provider_dispatch;
    return STATUS_SUCCESS;
}