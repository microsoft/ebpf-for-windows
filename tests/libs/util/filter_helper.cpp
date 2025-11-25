// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "catch_wrapper.hpp"
#include "filter_helper.h"

const GUID filter_helper::provider_guid = {
    0x3d6a3b42, 0x7c8e, 0x4f2a, {0x9b, 0x5d, 0x8f, 0x1a, 0x2e, 0x4c, 0x6b, 0x9d}};

const GUID filter_helper::sublayer_guid = {
    0x7f9e2a1c, 0x5b3d, 0x4e8f, {0xa2, 0x6c, 0x1d, 0x4b, 0x7e, 0x3a, 0x9f, 0x5c}};

filter_helper::filter_helper(bool egress, uint16_t test_port, ADDRESS_FAMILY address_family, IPPROTO protocol)
    : egress(egress), test_port(test_port), address_family(address_family), protocol(protocol)
{
    REQUIRE(FwpmEngineOpen(nullptr, RPC_C_AUTHN_DEFAULT, nullptr, nullptr, &wfp_engine) == ERROR_SUCCESS);

    auto cleanup_on_failure = std::unique_ptr<void, std::function<void(void*)>>(
        reinterpret_cast<void*>(1), // Dummy pointer, we only care about the deleter.
        [&](void*) { cleanup(); });

    REQUIRE(FwpmTransactionBegin(wfp_engine, 0) == ERROR_SUCCESS);
    {
        auto abort_on_failure = std::unique_ptr<void, std::function<void(void*)>>(
            reinterpret_cast<void*>(1), // Dummy pointer, we only care about the deleter.
            [&](void*) { FwpmTransactionAbort(wfp_engine); });
        // Add provider
        FWPM_PROVIDER provider = {};
        provider.providerKey = provider_guid;
        provider.displayData.name = const_cast<wchar_t*>(L"eBPF Test Provider");
        provider.flags = 0;

        DWORD result = FwpmProviderAdd(wfp_engine, &provider, nullptr);
        bool success_or_exists = (result == ERROR_SUCCESS || result == FWP_E_ALREADY_EXISTS);
        REQUIRE(success_or_exists);

        // Add sublayer
        FWPM_SUBLAYER sublayer = {};
        sublayer.subLayerKey = sublayer_guid;
        sublayer.displayData.name = const_cast<wchar_t*>(L"eBPF Test Sublayer");
        sublayer.providerKey = const_cast<GUID*>(&provider_guid);
        sublayer.weight = 0x8000;

        result = FwpmSubLayerAdd(wfp_engine, &sublayer, nullptr);
        success_or_exists = (result == ERROR_SUCCESS || result == FWP_E_ALREADY_EXISTS);
        REQUIRE(success_or_exists);

        // Add the block filter
        REQUIRE(add_block_filter() == ERROR_SUCCESS);

        [[maybe_unused]] auto _ = abort_on_failure.release();
        REQUIRE(FwpmTransactionCommit(wfp_engine) == ERROR_SUCCESS);
    }

    [[maybe_unused]] auto _ = cleanup_on_failure.release();
    initialized = true;
}

filter_helper::~filter_helper() { cleanup(); }

void
filter_helper::cleanup()
{
    if (wfp_engine != nullptr) {
        DWORD result = FwpmTransactionBegin(wfp_engine, 0);
        if (result == ERROR_SUCCESS) {
            for (uint64_t filter_id : filter_ids) {
                result = FwpmFilterDeleteById(wfp_engine, filter_id);
                if (result != ERROR_SUCCESS) {
                    printf("Failed to delete WFP filter during filter_helper cleanup. Error: 0x%lX\n", result);
                }
            }
            result = FwpmSubLayerDeleteByKey(wfp_engine, &sublayer_guid);
            if (result != ERROR_SUCCESS) {
                printf("Failed to delete WFP sublayer during filter_helper cleanup. Error: 0x%lX\n", result);
            }
            FwpmProviderDeleteByKey(wfp_engine, &provider_guid);
            if (result != ERROR_SUCCESS) {
                printf("Failed to delete WFP provider during filter_helper cleanup. Error: 0x%lX\n", result);
            }
            result = FwpmTransactionCommit(wfp_engine);
            if (result != ERROR_SUCCESS) {
                printf("Failed to commit WFP transaction for filter_helper cleanup. Error: 0x%lX\n", result);
            }
        } else {
            printf("Failed to begin WFP transaction for filter_helper cleanup. Error: 0x%lX\n", result);
        }
        result = FwpmEngineClose(wfp_engine);
        if (result != ERROR_SUCCESS) {
            printf("Failed to close WFP engine during filter_helper cleanup. Error: 0x%lX\n", result);
        }
        wfp_engine = nullptr;
    }
    filter_ids.clear();
}

DWORD
filter_helper::add_block_filter()
{
    FWPM_FILTER filter = {};
    uint64_t filter_id = 0;

    filter.layerKey = (address_family == AF_INET)
                          ? ((egress) ? FWPM_LAYER_ALE_AUTH_CONNECT_V4 : FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4)
                          : ((egress) ? FWPM_LAYER_ALE_AUTH_CONNECT_V6 : FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6);

    filter.displayData.name = const_cast<wchar_t*>(L"eBPF Test Soft Block Filter");
    filter.providerKey = const_cast<GUID*>(&provider_guid);
    filter.subLayerKey = sublayer_guid;
    filter.action.type = FWP_ACTION_BLOCK;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = 1; // Low priority so hard permits can override

    FWPM_FILTER_CONDITION condition = {};
    condition.fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
    condition.matchType = FWP_MATCH_EQUAL;
    condition.conditionValue.type = FWP_UINT16;
    condition.conditionValue.uint16 = test_port;

    filter.filterCondition = &condition;
    filter.numFilterConditions = 1;

    REQUIRE(FwpmFilterAdd(wfp_engine, &filter, nullptr, &filter_id) == ERROR_SUCCESS);
    filter_ids.push_back(filter_id);

    return ERROR_SUCCESS;
}