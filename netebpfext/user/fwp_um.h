// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once
#include <mutex>
#include <unordered_map>

typedef class _fwp_engine
{
  public:
    _fwp_engine() = default;

    uint32_t
    add_fwpm_callout(const FWPM_CALLOUT0* callout)
    {
        std::unique_lock l(lock);
        uint32_t id = next_id++;
        fwpm_callouts.insert({id, *callout});
        return id;
    }

    bool
    remove_fwpm_callout(size_t id)
    {
        std::unique_lock l(lock);
        return fwpm_callouts.erase(id) == 1;
    }

    uint32_t
    register_fwps_callout(const FWPS_CALLOUT3* callout)
    {
        std::unique_lock l(lock);
        uint32_t id = next_id++;
        fwps_callouts.insert({id, *callout});
        return id;
    }

    bool
    remove_fwps_callout(size_t id)
    {
        std::unique_lock l(lock);
        return fwps_callouts.erase(id) == 1;
    }

    uint32_t
    add_fwpm_filter(const FWPM_FILTER0* filter)
    {
        std::unique_lock l(lock);
        uint32_t id = next_id++;
        fwpm_filters.insert({id, *filter});
        return id;
    }

    bool
    remove_fwpm_filter(size_t id)
    {
        std::unique_lock l(lock);
        return fwpm_filters.erase(id) == 1;
    }

    uint32_t
    add_fwpm_sub_layer(const FWPM_SUBLAYER0* sub_layer)
    {
        std::unique_lock l(lock);
        uint32_t id = next_id++;
        fwpm_sub_layers.insert({id, *sub_layer});
        return id;
    }

    bool
    remove_fwpm_sub_layer(size_t id)
    {
        std::unique_lock l(lock);
        return fwpm_sub_layers.erase(id) == 1;
    }

    FWP_ACTION_TYPE
    classify_test_packet(_In_ const GUID* layer_guid, NET_IFINDEX if_index);

    FWP_ACTION_TYPE
    test_bind_ipv4();

    FWP_ACTION_TYPE
    test_cgroup_inet4_recv_accept();

    FWP_ACTION_TYPE
    test_cgroup_inet6_recv_accept();

    FWP_ACTION_TYPE
    test_cgroup_inet4_connect();

    FWP_ACTION_TYPE
    test_cgroup_inet6_connect();

    FWP_ACTION_TYPE
    test_sock_ops_v4();

    FWP_ACTION_TYPE
    test_sock_ops_v6();

    static _fwp_engine*
    get()
    {
        if (!_engine)
            _engine = std::make_unique<_fwp_engine>();
        return _engine.get();
    }

  private:
    FWP_ACTION_TYPE
    test_cgroup_sock_addr(
        uint16_t layer_id,
        _In_ const GUID& layer_guid,
        _In_ const GUID& sublayer_guid,
        _In_ FWPS_INCOMING_VALUE0* incomingValue);

    FWP_ACTION_TYPE
    test_callout(
        uint16_t layer_id,
        _In_ const GUID& layer_guid,
        _In_ const GUID& sublayer_guid,
        _In_ FWPS_INCOMING_VALUE0* incoming_value);

    _Ret_maybenull_ const FWPM_FILTER*
    get_fwpm_filter_with_context(_In_ const GUID& layer_guid)
    {
        for (auto& [first, filter] : fwpm_filters) {
            if (memcmp(&filter.layerKey, &layer_guid, sizeof(GUID)) == 0 && filter.rawContext != 0) {
                return &filter;
            }
        }
        return nullptr;
    }

    _Ret_maybenull_ const FWPM_FILTER*
    get_fwpm_filter_with_context(_In_ const GUID& layer_guid, _In_ const GUID& sublayer_guid)
    {
        for (auto& [first, filter] : fwpm_filters) {
            if (memcmp(&filter.layerKey, &layer_guid, sizeof(GUID)) == 0 &&
                memcmp(&filter.subLayerKey, &sublayer_guid, sizeof(GUID)) == 0 && filter.rawContext != 0) {
                return &filter;
            }
        }
        return nullptr;
    }

    _Ret_maybenull_ const GUID*
    get_callout_key_from_layer_guid(_In_ const GUID* layer_guid)
    {
        for (auto& [first, callout] : fwpm_callouts) {
            if (callout.applicableLayer == *layer_guid) {
                return &callout.calloutKey;
            }
        }
        return nullptr;
    }

    _Ret_maybenull_ const FWPS_CALLOUT3*
    get_callout_from_key(_In_ const GUID* callout_key)
    {
        for (auto& [first, callout] : fwps_callouts) {
            if (callout.calloutKey == *callout_key) {
                return &callout;
            }
        }
        return nullptr;
    }

    static std::unique_ptr<_fwp_engine> _engine;

    std::mutex lock;
    uint32_t next_id = 1;
    std::unordered_map<size_t, FWPS_CALLOUT3> fwps_callouts;
    std::unordered_map<size_t, FWPM_CALLOUT0> fwpm_callouts;
    std::unordered_map<size_t, FWPM_FILTER0> fwpm_filters;
    std::unordered_map<size_t, FWPM_SUBLAYER0> fwpm_sub_layers;
} fwp_engine;
