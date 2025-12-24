// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <fwpmu.h>
#include <stdexcept>
#include <string>
#include <vector>

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
    bool egress{false};
    bool initialized{false};

    void
    cleanup();
    DWORD
    add_block_filter();

  public:
    /**
     * @brief Construct filter helper and set up WFP soft block filter.
     *
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