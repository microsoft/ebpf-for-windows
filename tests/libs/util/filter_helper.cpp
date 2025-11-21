// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "filter_helper.h"

const GUID filter_helper::provider_guid = {
    0x12345678, 0x1234, 0x5678, {0x90, 0x12, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12}};

const GUID filter_helper::sublayer_guid = {
    0x87654321, 0x4321, 0x8765, {0x21, 0x09, 0x21, 0x09, 0x87, 0x65, 0x43, 0x21}};

filter_helper::filter_helper(bool egress, uint16_t test_port, ADDRESS_FAMILY address_family, IPPROTO protocol)
    : egress(egress), test_port(test_port), address_family(address_family), protocol(protocol)
{
    DWORD result = FwpmEngineOpen(nullptr, RPC_C_AUTHN_DEFAULT, nullptr, nullptr, &wfp_engine);
    if (result != ERROR_SUCCESS) {
        last_error = result;
        return;
    }

    result = FwpmTransactionBegin(wfp_engine, 0);
    if (result != ERROR_SUCCESS) {
        last_error = result;
        cleanup();
        return;
    }

    // Add provider
    FWPM_PROVIDER provider = {};
    provider.providerKey = provider_guid;
    provider.displayData.name = const_cast<wchar_t*>(L"eBPF Test Provider");
    provider.flags = 0;

    result = FwpmProviderAdd(wfp_engine, &provider, nullptr);
    if (result != ERROR_SUCCESS && result != FWP_E_ALREADY_EXISTS) {
        last_error = result;
        FwpmTransactionAbort(wfp_engine);
        cleanup();
        return;
    }

    // Add sublayer
    FWPM_SUBLAYER sublayer = {};
    sublayer.subLayerKey = sublayer_guid;
    sublayer.displayData.name = const_cast<wchar_t*>(L"eBPF Test Sublayer");
    sublayer.providerKey = const_cast<GUID*>(&provider_guid);
    sublayer.weight = 0x8000;

    result = FwpmSubLayerAdd(wfp_engine, &sublayer, nullptr);
    if (result != ERROR_SUCCESS && result != FWP_E_ALREADY_EXISTS) {
        last_error = result;
        FwpmTransactionAbort(wfp_engine);
        cleanup();
        return;
    }

    // Add the soft block filter
    result = add_soft_block_filter();
    if (result != ERROR_SUCCESS) {
        last_error = result;
        FwpmTransactionAbort(wfp_engine);
        cleanup();
        return;
    }

    result = FwpmTransactionCommit(wfp_engine);
    if (result != ERROR_SUCCESS) {
        last_error = result;
        cleanup();
        return;
    }

    initialized = true;
}

filter_helper::~filter_helper() { cleanup(); }

void
filter_helper::cleanup()
{
    if (wfp_engine != nullptr) {
        if (FwpmTransactionBegin(wfp_engine, 0) == ERROR_SUCCESS) {
            for (uint64_t filter_id : filter_ids) {
                FwpmFilterDeleteById(wfp_engine, filter_id);
            }
            FwpmSubLayerDeleteByKey(wfp_engine, &sublayer_guid);
            FwpmProviderDeleteByKey(wfp_engine, &provider_guid);
            FwpmTransactionCommit(wfp_engine);
        }
        FwpmEngineClose(wfp_engine);
        wfp_engine = nullptr;
    }
    filter_ids.clear();
}

DWORD
filter_helper::add_soft_block_filter()
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

    DWORD result = FwpmFilterAdd(wfp_engine, &filter, nullptr, &filter_id);
    if (result == ERROR_SUCCESS) {
        filter_ids.push_back(filter_id);
    }

    return result;
}