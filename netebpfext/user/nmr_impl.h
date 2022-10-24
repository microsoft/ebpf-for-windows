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
     * @return Handle to the provider registration.
     */
    nmr_provider_handle
    register_provider(_In_ const NPI_PROVIDER_CHARACTERISTICS& characteristics, _In_opt_ const void* context);

    /**
     * @brief Deregister a provider.
     *
     * @param[in] provider_handle Handle to the provider.
     * @retval true Caller needs to wait for the deregistration to complete.
     * @retval false Deregistration is complete.
     */
    bool
    deregister_provider(_In_ nmr_provider_handle provider_handle);

    /**
     * @brief Wait for deregistration to complete.
     *
     * @param[in] provider_handle Handle to the provider.
     */
    void
    wait_for_deregister_provider(_In_ nmr_provider_handle provider_handle);

    /**
     * @brief Register a client.
     *
     * @param[in] characteristics Characteristics of the client.
     * @param[in] context Context passed to the client.
     * @return Handle to the client registration.
     */
    nmr_client_handle
    register_client(_In_ const NPI_CLIENT_CHARACTERISTICS& characteristics, _In_opt_ const void* context);

    /**
     * @brief Deregister a client.
     *
     * @param[in] client_handle Handle to the client.
     * @retval true Caller needs to wait for the deregistration to complete.
     * @retval false Deregistration is complete.
     */
    bool
    deregister_client(_In_ nmr_client_handle client_handle);

    /**
     * @brief Wait for deregistration to complete.
     *
     * @param[in] client_handle Handle to the client.
     */
    void
    wait_for_deregister_client(_In_ nmr_client_handle client_handle);

    /**
     * @brief Signal that a client detach is complete.
     *
     * @param[in] binding_handle NMR binding handle.
     */
    void
    binding_detach_client_complete(_In_ nmr_binding_handle binding_handle);

    /**
     * @brief Signal that a provider detach is complete.
     *
     * @param[in] binding_handle NMR binding handle.
     */
    void
    binding_detach_provider_complete(_In_ nmr_binding_handle binding_handle);

    /**
     * @brief Callback from the client to complete an attach.
     *
     * @param[in] binding_handle Binding handle passed to the client.
     * @param[in] client_binding_context Client's per binding context.
     * @param[in] client_dispatch Client's dispatch table.
     * @param[out] provider_binding_context Provider's per binding context.
     * @param[out] provider_dispatch Provider's dispatch table.
     * @retval STATUS_SUCCESS The client module was successfully attached to the provider module.
     * @retval STATUS_NOINTERFACE The provider module did not attach to the client module.
     * @retval Other status codes An error occurred.
     */
    NTSTATUS
    client_attach_provider(
        _In_ nmr_binding_handle binding_handle,
        _In_ __drv_aliasesMem const void* client_binding_context,
        _In_ const void* client_dispatch,
        _Outptr_ const void** provider_binding_context,
        _Outptr_ const void** provider_dispatch);

  private:
    struct client_registration
    {
        const NPI_CLIENT_CHARACTERISTICS characteristics = {};
        const void* context = nullptr;
        volatile long long bindings = 0;
        bool deregistering = false;
    };

    struct provider_registration
    {
        const NPI_PROVIDER_CHARACTERISTICS characteristics = {};
        const void* context = nullptr;
        volatile long long bindings = 0;
        bool deregistering = false;
    };

    enum binding_status
    {
        Ready = 0,
        UnbindPending,
        UnbindComplete
    };

    struct binding
    {
        provider_registration& provider;
        client_registration& client;
        const void* provider_binding_context = nullptr;
        const void* provider_dispatch = nullptr;
        binding_status provider_binding_status = Ready;
        const void* client_binding_context = nullptr;
        const void* client_dispatch = nullptr;
        binding_status client_binding_status = Ready;
    };
    typedef std::function<void()> pending_action_t;

    // The NMR operations are mostly symmetric with respect to providers and
    // clients. As a result, the operations are implemented as a single set
    // templated function with the template parameter being the type of the
    // NMR entity being acted on (provider or client).

    /**
     * @brief Add a provider or client to the correct collection.
     *
     * @param[in,out] collection Collection to add to.
     * @param[in] characteristics Characteristics of the provider or client.
     * @param[in] context Context handle to return to the caller.
     * @return Handle to the provider or client.
     */
    template <typename collection_t, typename characteristics_t>
    collection_t::value_type::first_type
    add(_Inout_ collection_t& collection, _In_ const characteristics_t& characteristics, _In_opt_ const void* context);

    /**
     * @brief Begin the process of deregistering a provider or client.
     *
     * @param[in,out] collection Collection to deregister from.
     * @param[in] handle Handle to the provider or client.
     */
    template <typename collection_t>
    void
    deactivate(_Inout_ collection_t& collection, _In_ collection_t::value_type::first_type handle);

    /**
     * @brief Finish removing a provider or client from the correct collection.
     *
     * @param[in,out] collection Collection to remove from.
     * @param[in] handle Handle to the provider or client.
     */
    template <typename collection_t>
    void
    remove(_Inout_ collection_t& collection, _In_ collection_t::value_type::first_type handle);

    /**
     * @brief Perform a bind using an entry from the initiator_collection
     * and all entries from the target_collection.
     *
     * @param[in,out] initiator_collection Collection containing the initiator (can be either provider or client).
     * @param[in] handle Handle to the initiator.
     * @param[in,out] target_collection Collection containing all the targets (can be either provider or client).
     */
    template <typename initiator_collection_t, typename target_collection_t>
    void
    perform_bind(
        _Inout_ initiator_collection_t& initiator_collection,
        _In_ initiator_collection_t::value_type::first_type initiator_handle,
        _Inout_ target_collection_t& target_collection);

    /**
     * @brief Unbind a provider or client from all other providers or clients.
     *
     * @param[in,out] initiator_collection Collection containing the initiator (can be either provider or client).
     * @param[in] handle Handle to the initiator (can be either provider or client).
     * @retval true One or more bindings returned pending.
     * @retval false All bindings where successfully removed.
     */
    template <typename initiator_collection_t>
    bool
    perform_unbind(
        _Inout_ initiator_collection_t& initiator_collection,
        _In_ initiator_collection_t::value_type::first_type initiator_handle);

    /**
     * @brief Attempt to bind a client to a provider.
     *
     * @param[in,out] client Client to attempt to bind.
     * @param[in,out] provider Provider to attempt to bind to.
     * @return Contains a function to perform the bind if successful.
     */
    std::optional<pending_action_t>
    bind(_Inout_ client_registration& client, _Inout_ provider_registration& provider);

    /**
     * @brief Finish the process of unbinding a client from a provider.
     *
     * @param[in] binding_handle Binding handle to unbind.
     */
    void
    unbind_complete(_In_ nmr_binding_handle binding_handle);

    /**
     * @brief Start the process of unbinding a client from a provider.
     *
     * @param[in] binding_handle Binding handle to unbind.
     * @retval true Either the client or provider returned pending.
     * @retval false Both the client and provider returned successfully.
     */
    bool
    begin_unbind(_In_ nmr_binding_handle binding_handle);

    std::map<nmr_binding_handle, binding> bindings;
    std::map<nmr_provider_handle, provider_registration> providers;
    std::map<nmr_client_handle, client_registration> clients;

    size_t next_handle = 1;

    std::condition_variable bindings_changed;
    std::mutex lock;

} nmr_t;
