// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <comutil.h>
#include <fwpmu.h>
#include <netfw.h>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

/**
 * @brief WFP filter action for test filters.
 */
enum class wfp_filter_action
{
    block,
    permit,
};

/**
 * @brief Filter specification for tests.
 */
struct wfp_test_filter_spec
{
    GUID layer;
    std::optional<uint16_t> local_port;
    std::optional<uint16_t> remote_port;
    wfp_filter_action action{wfp_filter_action::block};
    uint8_t weight{1}; // Priority (lower = higher priority).
};

/**
 * @brief Helper class for managing Windows Filtering Platform (WFP) filters for testing.
 *
 * This class provides RAII management of WFP filters to support testing of eBPF hook behavior.
 *
 * @note Uses catch2 assertions to fail in case of errors during setup or cleanup.
 *
 */
class filter_helper
{
  private:
    static const GUID provider_guid;
    static const GUID sublayer_guid;

    HANDLE wfp_engine{};
    std::vector<uint64_t> filter_ids{};
    uint16_t test_port{};
    ADDRESS_FAMILY address_family{AF_INET};
    IPPROTO protocol{IPPROTO_TCP};
    bool initialized{false};

    void
    cleanup();

    /**
     * @brief Add a single WFP filter based on specification.
     *
     * Internal helper that creates a WFP filter from the test specification.
     * Must be called within an active WFP transaction.
     *
     * @param[in] filter_spec Filter specification containing layer, ports, action, and weight.
     *
     * @return ERROR_SUCCESS on success, Windows error code on failure.
     */
    DWORD
    add_filter(_In_ const wfp_test_filter_spec& filter_spec);

  public:
    /**
     * @brief Construct filter helper and set up WFP soft block filter.
     *
     * @param[in] egress Whether to create egress (connect) or ingress (recv_accept) filter.
     * @param[in] test_port Port to create soft block filter for.
     * @param[in] address_family AF_INET or AF_INET6.
     * @param[in] protocol IPPROTO_TCP or IPPROTO_UDP.
     */
    filter_helper(
        bool egress = false,
        uint16_t test_port = 8989,
        ADDRESS_FAMILY address_family = AF_INET,
        IPPROTO protocol = IPPROTO_TCP);

    /**
     * @brief Construct filter helper with multiple WFP filters.
     *
     * Creates a WFP provider, sublayer, and all specified filters in a single transaction.
     * All filters are added with the test sublayer and provider for easy cleanup.
     *
     * @param[in] filters Vector of filter specifications to apply.
     *
     * @exception std::exception Throws if WFP engine initialization or filter creation fails.
     */
    explicit filter_helper(_In_ const std::vector<wfp_test_filter_spec>& filters);

    /**
     * @brief Destructor - automatically cleans up WFP filters.
     */
    ~filter_helper();

    // Non-copyable.
    filter_helper(const filter_helper&) = delete;
    filter_helper&
    operator=(const filter_helper&) = delete;

    /**
     * @brief Check if helper was initialized successfully.
     */
    bool
    is_initialized() const
    {
        return initialized;
    }
};
