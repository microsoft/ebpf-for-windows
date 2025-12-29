// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "catch_wrapper.hpp"
#include "filter_helper.h"

const GUID filter_helper::provider_guid = {
    0x3d6a3b42, 0x7c8e, 0x4f2a, {0x9b, 0x5d, 0x8f, 0x1a, 0x2e, 0x4c, 0x6b, 0x9d}};

const GUID filter_helper::sublayer_guid = {
    0x7f9e2a1c, 0x5b3d, 0x4e8f, {0xa2, 0x6c, 0x1d, 0x4b, 0x7e, 0x3a, 0x9f, 0x5c}};

filter_helper::filter_helper(const std::vector<wfp_test_filter_spec>& filters)
{
    REQUIRE(FwpmEngineOpen(nullptr, RPC_C_AUTHN_DEFAULT, nullptr, nullptr, &wfp_engine) == ERROR_SUCCESS);

    auto cleanup_on_failure = std::unique_ptr<void, std::function<void(void*)>>(
        reinterpret_cast<void*>(1), // Dummy pointer, we only care about the deleter.
        [&](void*) { cleanup(); });

    REQUIRE(FwpmTransactionBegin(wfp_engine, 0) == ERROR_SUCCESS);
    auto abort_on_failure = std::unique_ptr<void, std::function<void(void*)>>(
        reinterpret_cast<void*>(1), // Dummy pointer, we only care about the deleter.
        [&](void*) { FwpmTransactionAbort(wfp_engine); });
    // Add provider.
    FWPM_PROVIDER provider = {};
    provider.providerKey = provider_guid;
    provider.displayData.name = const_cast<wchar_t*>(L"eBPF Test Provider");
    provider.flags = 0;

    DWORD result = FwpmProviderAdd(wfp_engine, &provider, nullptr);
    bool success_or_exists = (result == ERROR_SUCCESS || result == FWP_E_ALREADY_EXISTS);
    REQUIRE(success_or_exists);

    // Add sublayer.
    FWPM_SUBLAYER sublayer = {};
    sublayer.subLayerKey = sublayer_guid;
    sublayer.displayData.name = const_cast<wchar_t*>(L"eBPF Test Sublayer");
    sublayer.providerKey = const_cast<GUID*>(&provider_guid);
    sublayer.weight = 0x8000;

    result = FwpmSubLayerAdd(wfp_engine, &sublayer, nullptr);
    success_or_exists = (result == ERROR_SUCCESS || result == FWP_E_ALREADY_EXISTS);
    REQUIRE(success_or_exists);

    // Add all specified filters.
    for (const auto& filter_spec : filters) {
        REQUIRE(add_filter(filter_spec) == ERROR_SUCCESS);
    }

    (void)abort_on_failure.release();
    REQUIRE(FwpmTransactionCommit(wfp_engine) == ERROR_SUCCESS);
    (void)cleanup_on_failure.release();

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
filter_helper::add_filter(const wfp_test_filter_spec& filter_spec)
{
    FWPM_FILTER filter = {};
    uint64_t filter_id = 0;

    filter.layerKey = filter_spec.layer;
    filter.displayData.name = const_cast<wchar_t*>(L"eBPF Test Filter");
    filter.providerKey = const_cast<GUID*>(&provider_guid);
    filter.subLayerKey = sublayer_guid;

    // Map wfp_filter_action to FWP action type.
    switch (filter_spec.action) {
    case wfp_filter_action::block:
        filter.action.type = FWP_ACTION_BLOCK;
        break;
    case wfp_filter_action::permit:
        filter.action.type = FWP_ACTION_PERMIT;
        break;
    }

    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = filter_spec.weight;

    // Require at least one port to be specified.
    if (!filter_spec.local_port.has_value() && !filter_spec.remote_port.has_value()) {
        return ERROR_INVALID_PARAMETER;
    }

    // Build conditions array for local and/or remote port.
    FWPM_FILTER_CONDITION conditions[2] = {}; // Max 2 conditions: local and remote port.
    UINT32 condition_count = 0;

    if (filter_spec.local_port.has_value()) {
        conditions[condition_count].fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
        conditions[condition_count].matchType = FWP_MATCH_EQUAL;
        conditions[condition_count].conditionValue.type = FWP_UINT16;
        conditions[condition_count].conditionValue.uint16 = filter_spec.local_port.value();
        condition_count++;
    }

    if (filter_spec.remote_port.has_value()) {
        conditions[condition_count].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
        conditions[condition_count].matchType = FWP_MATCH_EQUAL;
        conditions[condition_count].conditionValue.type = FWP_UINT16;
        conditions[condition_count].conditionValue.uint16 = filter_spec.remote_port.value();
        condition_count++;
    }

    filter.filterCondition = conditions;
    filter.numFilterConditions = condition_count;

    auto result = FwpmFilterAdd(wfp_engine, &filter, nullptr, &filter_id);
    if (result == ERROR_SUCCESS) {
        filter_ids.push_back(filter_id);
    }

    return result;
}