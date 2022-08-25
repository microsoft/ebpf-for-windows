// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <condition_variable>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <vector>

#include <ebpf_platform.h>
#include <kernel_um.h>
#include <netiodef.h>
#include <../km/netioddk.h>

typedef class _nmr
{
  public:
    typedef void* nmr_provider_handle;
    typedef void* nmr_client_handle;
    typedef void* nmr_binding_handle;

    _nmr() = default;
    ~_nmr() = default;

    /**
     * @brief Register a provider.
     *
     * @param[in] characteristics Characteristics of the provider.
     * @param[in] context Context passed to the provider.
     * @return nmr_handle
     */
    nmr_provider_handle
    register_provider(const NPI_PROVIDER_CHARACTERISTICS& characteristics, _In_opt_ void* context);

    /**
     * @brief Deregister a provider.
     *
     * @param[in] provider_handle Handle to the provider.
     * @return true Caller needs to wait for the deregistering to complete.
     * @return false Dergistering is complete.
     */
    bool
    deregister_provider(nmr_provider_handle provider_handle);

    /**
     * @brief Wait for a deregistering to complete.
     *
     * @param[in] provider_handle Handle to the provider.
     */
    void
    wait_for_deregister_provider(nmr_provider_handle provider_handle);

    /**
     * @brief Register a client.
     *
     * @param[in] characteristics Characteristics of the client.
     * @param[in] context Context passed to the client.
     * @return nmr_handle
     */
    nmr_client_handle
    register_client(const NPI_CLIENT_CHARACTERISTICS& characteristics, _In_ void* context);

    /**
     * @brief Dergister a client.
     *
     * @param[in] client_handle Handle to the client.
     * @return true Caller needs to wait for the deregistering to complete.
     * @return false Dergistering is complete.
     */
    bool
    deregister_client(nmr_client_handle client_handle);

    /**
     * @brief Wait for a deregistering to complete.
     *
     * @param[in] client_handle Handle to the client.
     */
    void
    wait_for_deregister_client(nmr_client_handle client_handle);

    /**
     * @brief Signal that a detach is complete.
     *
     * @param[in] binding_handle NMR binding handle.
     */
    void
    binding_detach_complete(nmr_client_handle binding_handle);

    /**
     * @brief Callback from the client to complete an attach.
     *
     * @param[in] binding_handle Binding handle passed to the client.
     * @param[in] client_binding_context Client's per binding context.
     * @param[in] client_dispatch Client's dispatch table.
     * @param[out] provider_binding_context Provider's per binding context.
     * @param[out] provider_dispatch Provider's dispatch table.
     * @return NTSTATUS return from ProviderAttachClient.
     */
    NTSTATUS
    client_attach_provider(
        nmr_binding_handle binding_handle,
        _In_ __drv_aliasesMem void* client_binding_context,
        _In_ const void* client_dispatch,
        _Out_ void** provider_binding_context,
        _Out_ const void** provider_dispatch);

  private:
    struct client_registration
    {
        NPI_CLIENT_CHARACTERISTICS characteristics = {};
        void* context = nullptr;
        size_t bindings = 0;
        bool deregistering = false;
    };

    struct provider_registration
    {
        NPI_PROVIDER_CHARACTERISTICS characteristics = {};
        void* context = nullptr;
        size_t bindings = 0;
        bool deregistering = false;
    };

    struct binding
    {
        provider_registration& provider;
        client_registration& client;
        void* provider_binding_context = nullptr;
        const void* provider_dispatch = nullptr;
        void* client_binding_context = nullptr;
        const void* client_dispatch = nullptr;
    };
    typedef std::function<void()> pending_action_t;

    // The NMR operations are mostly symetric with respect to providers and
    // clients. As a result, the operations are implemented as a single set
    // templated function with the template parameter being the type of the
    // NMR entity being acted on (provider or client).

    /**
     * @brief Add a provider or client to the correct collection.
     *
     * @param[in] collection Collection to add to.
     * @param[in] characteristics Characteristics of the provider or client.
     * @param[in] context Context handle to return to the caller.
     * @return nmr_handle Handle to the provider or client.
     */
    template <typename collection_t, typename characteristics_t>
    collection_t::value_type::first_type
    add(collection_t& collection, characteristics_t& characteristics, void* context);

    /**
     * @brief Begin the process of deregistering a provider or client.
     *
     * @param[in] collection Collection to deregister from.
     * @param[in] handle Handle to the provider or client.
     */
    template <typename collection_t>
    void
    deactivate(collection_t& collection, collection_t::value_type::first_type handle);

    /**
     * @brief Finish removing a provider or client from the correct collection.
     *
     * @param[in] collection Collection to remove from.
     * @param[in] handle Handle to the provider or client.
     */
    template <typename collection_t>
    void
    remove(collection_t& collection, collection_t::value_type::first_type handle);

    /**
     * @brief Perform the a bind using an entry from the initiator_collection
     * and all entries from the target_collection.
     *
     * @param[in] initiator_collection Collection containing the initiator (can be either provider or client).
     * @param[in] handle Handle to the initiator.
     * @param[in] target_collection Collection containing all the targets (can be either provider or client).
     */
    template <typename initiator_collection_t, typename target_collection_t>
    void
    perform_bind(
        initiator_collection_t& initiator_collection,
        initiator_collection_t::value_type::first_type initiator_handle,
        target_collection_t& target_collection);

    /**
     * @brief Unbind a provider or client from all other providers or clients.
     *
     * @param[in] initiator_collection Collection containing the initiator (can be either provider or client).
     * @param[in] handle Handle to the initiator  (can be either provider or client)..
     * @return true One or more bindings returned pending.
     * @return false All bindings where successfully removed.
     */
    template <typename initiator_collection_t>
    bool
    perform_unbind(
        initiator_collection_t& initiator_collection, initiator_collection_t::value_type::first_type initiator_handle);

    /**
     * @brief Attempt to bind a client to a provider.
     *
     * @param[in] client Client to attempt to bind.
     * @param[in] provider Provider to attempt to bind to.
     * @return Contains a function to perform the bind if successful.
     */
    std::optional<pending_action_t>
    bind(client_registration& client, provider_registration& provider);

    /**
     * @brief Finish the process of unbinding a client from a provider.
     *
     * @param[in] binding_handle Binding handle to unbind.
     */
    void
    unbind_complete(nmr_binding_handle binding_handle);

    /**
     * @brief Start the process of unbinding a client from a provider.
     *
     * @param[in] binding_handle Binding handle to unbind.
     * @return true Either the client or provider returned pending.
     * @return false Both the client and provider returned successfully.
     */
    bool
    unbind(nmr_binding_handle binding_handle);

    std::map<nmr_binding_handle, binding> bindings;
    std::map<nmr_provider_handle, provider_registration> providers;
    std::map<nmr_client_handle, client_registration> clients;

    size_t next_handle = 1;

    std::condition_variable bindings_changed;
    std::mutex lock;

} nmr_t;
