// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <fwpmu.h>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

// Windows Firewall COM API
#include <comutil.h>
#include <netfw.h>
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
    uint8_t weight{1}; // Priority (lower = higher priority)
};

/**
 * @brief Helper class for managing Windows Filtering Platform (WFP) filters for testing.
 *
 * This class provides RAII management of WFP filters to enable testing of hard/soft permit
 * functionality. It creates a low-priority soft block filter that can be bypassed by
 * higher-priority hard permit filters.
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
    DWORD
    add_filter(const wfp_test_filter_spec& filter_spec);

  public:
    /**
     * @brief Construct filter helper and set up WFP soft block filter.
     *
     * @param egress Whether to create egress (connect) or ingress (recv_accept) filter
     * @param test_port Port to create soft block filter for
     * @param address_family AF_INET or AF_INET6
     * @param protocol IPPROTO_TCP or IPPROTO_UDP
     */
    filter_helper(
        bool egress = false,
        uint16_t test_port = 8989,
        ADDRESS_FAMILY address_family = AF_INET,
        IPPROTO protocol = IPPROTO_TCP);

    /**
     * @brief Construct filter helper with multiple WFP filters.
     * @param filters Vector of filter specifications to apply
     */
    filter_helper(const std::vector<wfp_test_filter_spec>& filters);

    /**
     * @brief Destructor - automatically cleans up WFP filters.
     */
    ~filter_helper();

    // Non-copyable
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
