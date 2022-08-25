// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "nmr_impl.h"

_nmr::nmr_provider_handle
_nmr::register_provider(const NPI_PROVIDER_CHARACTERISTICS& characteristics, _In_opt_ void* context)
{
    // Add the provider to the list of providers.
    nmr_provider_handle provider_handle = add(providers, characteristics, context);
    // Notify existing clients about the new provider.
    perform_bind(providers, provider_handle, clients);
    return provider_handle;
}

bool
_nmr::deregister_provider(nmr_provider_handle provider_handle)
{
    // Remove the provider from the list of providers.
    deactivate(providers, provider_handle);
    // If the unbind returned pending, then the caller needs to wait for the unbind to complete.
    if (perform_unbind(providers, provider_handle)) {
        // Pending unbind.
        return true;
    }
    // Unbind is complete.
    remove(providers, provider_handle);
    return false;
}

void
_nmr::wait_for_deregister_provider(nmr_provider_handle provider_handle)
{
    // Wait for the unbind to complete.
    remove(providers, provider_handle);
}

_nmr::nmr_client_handle
_nmr::register_client(const NPI_CLIENT_CHARACTERISTICS& characteristics, _In_opt_ void* context)
{
    // Add the client to the list of clients.
    nmr_client_handle client_handle = add(clients, characteristics, context);
    // Notify existing providers about the new client.
    perform_bind(clients, client_handle, providers);
    return client_handle;
}

bool
_nmr::deregister_client(nmr_client_handle client_handle)
{
    // Remove the client from the list of clients.
    deactivate(clients, client_handle);
    // If the unbind returned pending, then the caller needs to wait for the unbind to complete.
    if (perform_unbind(clients, client_handle)) {
        // Pending unbind.
        return true;
    }
    // Unbind is complete.
    remove(clients, client_handle);
    return false;
}

void
_nmr::wait_for_deregister_client(nmr_client_handle client_handle)
{
    // Wait for the unbind to complete.
    remove(clients, client_handle);
}

void
_nmr::binding_detach_complete(nmr_binding_handle binding_handle)
{
    // Signal the detach complete.
    unbind_complete(binding_handle);
}

NTSTATUS
_nmr::client_attach_provider(
    nmr_binding_handle binding_handle,
    _In_ __drv_aliasesMem void* client_binding_context,
    _In_ const void* client_dispatch,
    _Out_ void** provider_binding_context,
    _Out_ const void** provider_dispatch)
{
    std::unique_lock l(lock);
    // Resolve the binding_handle to the binding.
    auto it = bindings.find(binding_handle);
    if (it == bindings.end()) {
        throw std::runtime_error("invalid handle");
    }
    auto& binding = it->second;

    // Save the client's per binding context and dispatch table.
    binding.client_binding_context = client_binding_context;
    binding.client_dispatch = client_dispatch;
    l.unlock();

    // Call the provider's attach client.
    NTSTATUS status = binding.provider.characteristics.ProviderAttachClient(
        binding_handle,
        binding.provider.context,
        &binding.client.characteristics.ClientRegistrationInstance,
        client_binding_context,
        client_dispatch,
        &binding.provider_binding_context,
        &binding.provider_dispatch);

    // If successful, save the provider's per binding context and dispatch table.
    if (NT_SUCCESS(status)) {
        *provider_binding_context = binding.provider_binding_context;
        *provider_dispatch = binding.provider_dispatch;
    }
    return status;
}

std::optional<_nmr::pending_action_t>
_nmr::bind(client_registration& client, provider_registration& provider)
{
    // Match on NPI ID
    if (*client.characteristics.ClientRegistrationInstance.NpiId !=
        *provider.characteristics.ProviderRegistrationInstance.NpiId) {
        return std::nullopt;
    }

    // Skip if client or provider are deregestering.
    if (client.deregistering || provider.deregistering) {
        return std::nullopt;
    }

    // Acquire references on both client and provider to prevent them from unloading.
    client.bindings++;
    provider.bindings++;

    nmr_binding_handle h = reinterpret_cast<nmr_binding_handle>(next_handle++);
    bindings.insert({h, {provider, client}});

    return {[&client, &provider, h, this]() {
        NTSTATUS status = client.characteristics.ClientAttachProvider(
            h, client.context, &provider.characteristics.ProviderRegistrationInstance);
        if (!NT_SUCCESS(status)) {
            unbind_complete(h);
        }
    }};
}

void
_nmr::unbind_complete(nmr_binding_handle binding_handle)
{
    std::unique_lock l(lock);
    auto it = bindings.find(binding_handle);
    if (it == bindings.end()) {
        throw std::runtime_error("invalid handle");
    }
    auto& binding = it->second;

    // Notify the client that that the binding context can be freed.
    binding.client.characteristics.ClientCleanupBindingContext(binding.client_binding_context);

    // Notify the provider that that the binding context can be freed.
    binding.provider.characteristics.ProviderCleanupBindingContext(binding.provider_binding_context);

    binding.provider.bindings--;
    binding.client.bindings--;
    bindings.erase(it);

    // Notify the client or provider to check if they have any pending bindings.
    bindings_changed.notify_all();
}

bool
_nmr::unbind(nmr_binding_handle binding_handle)
{
    std::unique_lock l(lock);
    auto it = bindings.find(binding_handle);
    if (it == bindings.end()) {
        throw std::runtime_error("invalid handle");
    }

    auto& binding = it->second;
    l.unlock();
    NTSTATUS client_detach_status = binding.client.characteristics.ClientDetachProvider(binding.client_binding_context);
    NTSTATUS provider_detach_status =
        binding.provider.characteristics.ProviderDetachClient(binding.provider_binding_context);
    if (NT_SUCCESS(client_detach_status) && NT_SUCCESS(provider_detach_status)) {
        unbind_complete(binding_handle);
        return false;
    }
    return true;
}

template <typename collection_t, typename characteristics_t>
collection_t::value_type::first_type
_nmr::add(collection_t& collection, characteristics_t& characteristics, void* context)
{
    std::unique_lock l(lock);
    auto handle = reinterpret_cast<collection_t::value_type::first_type>(next_handle++);
    collection.insert({handle, {characteristics, context}});
    return handle;
}

template <typename collection_t>
void
_nmr::deactivate(collection_t& collection, collection_t::value_type::first_type handle)
{
    std::unique_lock l(lock);
    auto it = collection.find(handle);
    if (it == collection.end()) {
        throw std::runtime_error("invalid handle");
    }

    // Block new bindings.
    it->second.deregistering = true;
}

template <typename collection_t>
void
_nmr::remove(collection_t& collection, collection_t::value_type::first_type handle)
{
    std::unique_lock l(lock);
    auto it = collection.find(handle);
    if (it == collection.end()) {
        throw std::runtime_error("invalid handle");
    }

    // Wait for bindings to reach zero if requested
    if (it->second.bindings > 0) {
        bindings_changed.wait(l, [&]() { return it->second.bindings == 0; });
    }

    collection.erase(it);
}

template <typename initiator_collection_t, typename target_collection_t>
void
_nmr::perform_bind(
    initiator_collection_t& initiator_collection,
    initiator_collection_t::value_type::first_type initiator_handle,
    target_collection_t& target_collection)
{
    // Queue up the bind for each target to performed outside the lock.
    std::vector<pending_action_t> pending_actions;
    std::unique_lock l(lock);
    auto it = initiator_collection.find(initiator_handle);
    if (it == initiator_collection.end()) {
        throw std::runtime_error("invalid handle");
    }
    auto& initiator = it->second;
    for (auto& [target_handle, target] : target_collection) {
        // If the initiator is a client, then the target must be a provider.
        if constexpr (std::is_same<initiator_collection_t::value_type::second_type, client_registration>::value) {
            auto result = bind(initiator, target);
            if (result.has_value()) {
                pending_actions.push_back(result.value());
            }
        }
        // If the initiator is a provider, then the target must be a client.
        if constexpr (std::is_same<initiator_collection_t::value_type::second_type, provider_registration>::value) {
            auto result = bind(target, initiator);
            if (result.has_value()) {
                pending_actions.push_back(result.value());
            }
        }
    }
    l.unlock();
    for (auto& action : pending_actions) {
        action();
    }
}

template <typename initiator_collection_t>
bool
_nmr::perform_unbind(
    initiator_collection_t& initiator_collection, initiator_collection_t::value_type::first_type initiator_handle)
{
    bool pending = false;
    std::vector<nmr_binding_handle> handles_to_unbind;
    std::unique_lock l(lock);
    auto it = initiator_collection.find(initiator_handle);
    if (it == initiator_collection.end()) {
        throw std::runtime_error("invalid handle");
    }
    auto& initiator = it->second;
    // Find all the bindings that have the initiator as the client or provider.
    for (auto& [binding_handle, binding] : bindings) {
        // If the initiator is a client, then the target must be a provider.
        if constexpr (std::is_same<initiator_collection_t::value_type::second_type, client_registration>::value) {
            if (&binding.client == &initiator) {
                handles_to_unbind.push_back(binding_handle);
            }
        }
        // If the inititor is a provider, the the target must be a client.
        if constexpr (std::is_same<initiator_collection_t::value_type::second_type, provider_registration>::value) {
            if (&binding.provider == &initiator) {
                handles_to_unbind.push_back(binding_handle);
            }
        }
    }
    l.unlock();
    for (auto& binding_handle : handles_to_unbind) {
        pending |= unbind(binding_handle);
    }
    return pending;
}
