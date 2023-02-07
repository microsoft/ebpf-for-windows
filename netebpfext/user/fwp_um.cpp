// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "fwp_um.h"
#include "net_ebpf_ext_sock_addr.h"
#include "netebpfext_platform.h"

// 98849e12-b07d-11ec-9a30-18602489beee
DEFINE_GUID(
    EBPF_HOOK_CGROUP_CONNECT_V4_SUBLAYER, 0x98849e12, 0xb07d, 0x11ec, 0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee);

// 98849e13-b07d-11ec-9a30-18602489beee
DEFINE_GUID(
    EBPF_HOOK_CGROUP_CONNECT_V6_SUBLAYER, 0x98849e13, 0xb07d, 0x11ec, 0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee);

// Default eBPF WFP Sublayer GUID.
// 7c7b3fb9-3331-436a-98e1-b901df457fff
DEFINE_GUID(EBPF_DEFAULT_SUBLAYER, 0x7c7b3fb9, 0x3331, 0x436a, 0x98, 0xe1, 0xb9, 0x01, 0xdf, 0x45, 0x7f, 0xff);

std::unique_ptr<_fwp_engine> _fwp_engine::_engine;

// Attempt to classify a test packet at a given WFP layer on a given interface index.
// This is used to test the xdp hook.
FWP_ACTION_TYPE
_fwp_engine::classify_test_packet(_In_ const GUID* layer_guid, NET_IFINDEX if_index)
{
    std::unique_lock l(lock);
    const GUID* callout_key = get_callout_key_from_layer_guid(layer_guid);
    if (callout_key == nullptr) {
        return FWP_ACTION_CALLOUT_UNKNOWN;
    }
    const FWPS_CALLOUT3* callout = get_callout_from_key(callout_key);
    if (callout == nullptr) {
        return FWP_ACTION_CALLOUT_UNKNOWN;
    }
    FWPS_CLASSIFY_OUT0 result = {};
    FWPS_INCOMING_VALUE0 incoming_value[FWPS_FIELD_INBOUND_MAC_FRAME_NATIVE_MAX] = {};
    FWPS_INCOMING_VALUES incoming_fixed_values = {.incomingValue = incoming_value};
    incoming_fixed_values.incomingValue[FWPS_FIELD_INBOUND_MAC_FRAME_NATIVE_INTERFACE_INDEX].value.uint32 = if_index;
    FWPS_INCOMING_METADATA_VALUES incoming_metadata_values = {};
    const FWPM_FILTER* fwpm_filter = get_fwpm_filter_with_context(*layer_guid);
    if (!fwpm_filter) {
        return FWP_ACTION_CALLOUT_UNKNOWN;
    }
    FWPS_FILTER fwps_filter = {.context = fwpm_filter->rawContext};
    NET_BUFFER_LIST_POOL_PARAMETERS pool_parameters = {};
    std::unique_ptr<void, decltype(&NdisFreeNetBufferListPool)> nbl_pool_handle(
        NdisAllocateNetBufferListPool(nullptr, &pool_parameters), NdisFreeNetBufferListPool);
    if (!nbl_pool_handle) {
        return FWP_ACTION_CALLOUT_UNKNOWN;
    }

    std::unique_ptr<NET_BUFFER_LIST, decltype(&NdisFreeNetBufferList)> nbl(
        NdisAllocateNetBufferList(nbl_pool_handle.get(), 0, 0), NdisFreeNetBufferList);
    if (!nbl) {
        return FWP_ACTION_CALLOUT_UNKNOWN;
    }

    ULONG data = 0;
    std::unique_ptr<MDL, decltype(&IoFreeMdl)> mdl_chain(
        IoAllocateMdl(&data, sizeof(data), FALSE, FALSE, nullptr), IoFreeMdl);
    if (!mdl_chain) {
        return FWP_ACTION_CALLOUT_UNKNOWN;
    }

    std::unique_ptr<NET_BUFFER, decltype(&NdisFreeNetBuffer)> nb(
        NdisAllocateNetBuffer(nbl_pool_handle.get(), mdl_chain.get(), 0, sizeof(data)), NdisFreeNetBuffer);
    if (!nb) {
        return FWP_ACTION_CALLOUT_UNKNOWN;
    }

    nbl->FirstNetBuffer = nb.get();
    callout->classifyFn(
        &incoming_fixed_values,
        &incoming_metadata_values,
        nbl.get(),
        nullptr, // classifyContext,
        &fwps_filter,
        0, // flowContext,
        &result);

    return result.actionType;
}

constexpr uint32_t _test_destination_ipv4_address = 0x01020304;
static FWP_BYTE_ARRAY16 _test_destination_ipv6_address = {1, 2, 3, 4};
constexpr uint16_t _test_destination_port = 1234;
constexpr uint32_t _test_source_ipv4_address = 0x05060708;
static FWP_BYTE_ARRAY16 _test_source_ipv6_address = {5, 6, 7, 8};
constexpr uint16_t _test_source_port = 5678;
constexpr uint8_t _test_protocol = IPPROTO_TCP;
constexpr uint32_t _test_compartment_id = 1;
static FWP_BYTE_BLOB _test_app_id = {.size = 2, .data = (uint8_t*)"\\"};
static uint64_t _test_interface_luid = 1;
static TOKEN_ACCESS_INFORMATION _test_token_access_information = {0};
static FWP_BYTE_BLOB _test_user_id = {
    .size = (sizeof(TOKEN_ACCESS_INFORMATION)), .data = (uint8_t*)&_test_token_access_information};

// This is used to test the bind hook.
FWP_ACTION_TYPE
_fwp_engine::test_bind_ipv4()
{
    std::unique_lock l(lock);

    FWPS_INCOMING_VALUE0 incoming_value[FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_MAX] = {};
    incoming_value[FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_IP_LOCAL_PORT].value.uint16 = _test_destination_port;
    incoming_value[FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_IP_LOCAL_ADDRESS].value.uint32 =
        _test_destination_ipv4_address;
    incoming_value[FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_IP_PROTOCOL].value.uint8 = _test_protocol;
    incoming_value[FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_ALE_APP_ID].value.byteBlob = &_test_app_id;

    return test_callout(
        FWPS_LAYER_ALE_RESOURCE_ASSIGNMENT_V4,
        FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4,
        EBPF_DEFAULT_SUBLAYER,
        incoming_value);
}

FWP_ACTION_TYPE
_fwp_engine::test_callout(
    uint16_t layer_id,
    _In_ const GUID& layer_guid,
    _In_ const GUID& sublayer_guid,
    _In_ FWPS_INCOMING_VALUE0* incoming_value)
{
    FWPS_INCOMING_VALUES incoming_fixed_values = {.layerId = layer_id, .incomingValue = incoming_value};
    FWPS_INCOMING_METADATA_VALUES incoming_metadata_values = {};
    const FWPM_FILTER* fwpm_filter = get_fwpm_filter_with_context(layer_guid, sublayer_guid);
    if (!fwpm_filter) {
        return FWP_ACTION_CALLOUT_UNKNOWN;
    }
    FWPS_FILTER fwps_filter = {.context = fwpm_filter->rawContext};

    const GUID* callout_key = get_callout_key_from_layer_guid(&layer_guid);
    if (callout_key == nullptr) {
        return FWP_ACTION_CALLOUT_UNKNOWN;
    }

    const FWPS_CALLOUT3* callout = get_callout_from_key(callout_key);
    if (callout == nullptr) {
        return FWP_ACTION_CALLOUT_UNKNOWN;
    }

    FWPS_CLASSIFY_OUT0 result = {};
    result.rights = FWPS_RIGHT_ACTION_WRITE;
    callout->classifyFn(
        &incoming_fixed_values,
        &incoming_metadata_values,
        nullptr, // layer_data
        nullptr, // classify_context,
        &fwps_filter,
        0, // flow_context,
        &result);

    return result.actionType;
}

// This is used to test CGROUP_SOCK_ADDR hooks.
FWP_ACTION_TYPE
_fwp_engine::test_cgroup_sock_addr(
    uint16_t layer_id,
    _In_ const GUID& layer_guid,
    _In_ const GUID& sublayer_guid,
    _In_ FWPS_INCOMING_VALUE0* incoming_value)
{
    GUID filter_key = {};
    FWPS_FILTER filter = {};
    net_ebpf_ext_connect_redirect_filter_change_notify(FWPS_CALLOUT_NOTIFY_ADD_FILTER, &filter_key, &filter);

    FWP_ACTION_TYPE action_type = test_callout(layer_id, layer_guid, sublayer_guid, incoming_value);

    net_ebpf_ext_connect_redirect_filter_change_notify(FWPS_CALLOUT_NOTIFY_DELETE_FILTER, &filter_key, &filter);

    return action_type;
}

// This is used to test the INET4_RECV_ADDEPT hook.
FWP_ACTION_TYPE
_fwp_engine::test_cgroup_inet4_recv_accept()
{
    std::unique_lock l(lock);

    FWPS_INCOMING_VALUE0 incoming_value[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_MAX] = {};
    incoming_value[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS].value.uint32 = _test_destination_ipv4_address;
    incoming_value[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT].value.uint16 = _test_destination_port;
    incoming_value[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS].value.uint32 = _test_source_ipv4_address;
    incoming_value[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT].value.uint16 = _test_source_port;
    incoming_value[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL].value.uint8 = _test_protocol;
    incoming_value[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_COMPARTMENT_ID].value.uint32 = _test_compartment_id;
    incoming_value[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_INTERFACE].value.uint64 = &_test_interface_luid;
    incoming_value[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_ALE_APP_ID].value.byteBlob = &_test_app_id;
    incoming_value[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_ALE_USER_ID].value.byteBlob = &_test_user_id;

    return test_cgroup_sock_addr(
        FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, EBPF_DEFAULT_SUBLAYER, incoming_value);
}

// This is used to test the INET6_RECV_ADDEPT hook.
FWP_ACTION_TYPE
_fwp_engine::test_cgroup_inet6_recv_accept()
{
    std::unique_lock l(lock);

    FWPS_INCOMING_VALUE0 incoming_value[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_MAX] = {};
    incoming_value[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_ADDRESS].value.byteArray16 =
        &_test_destination_ipv6_address;
    incoming_value[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_PORT].value.uint16 = _test_destination_port;
    incoming_value[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_ADDRESS].value.byteArray16 = &_test_source_ipv6_address;
    incoming_value[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_PORT].value.uint16 = _test_source_port;
    incoming_value[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_PROTOCOL].value.uint8 = _test_protocol;
    incoming_value[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_COMPARTMENT_ID].value.uint32 = _test_compartment_id;
    incoming_value[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_INTERFACE].value.uint64 = &_test_interface_luid;
    incoming_value[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_ALE_APP_ID].value.byteBlob = &_test_app_id;
    incoming_value[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_ALE_USER_ID].value.byteBlob = &_test_user_id;

    return test_cgroup_sock_addr(
        FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, EBPF_DEFAULT_SUBLAYER, incoming_value);
}

// This is used to test the INET4_CONNECT hook.
FWP_ACTION_TYPE
_fwp_engine::test_cgroup_inet4_connect()
{
    FWP_ACTION_TYPE action;
    std::unique_lock l(lock);

    // For CGROUP_CONNECT* attach type, first CONNECT_REDIRECT callout is invoked, followed by
    // AUTH_CONNECT.
    FWPS_INCOMING_VALUE0 incoming_value[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_MAX] = {};
    incoming_value[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_LOCAL_ADDRESS].value.uint32 = _test_source_ipv4_address;
    incoming_value[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_LOCAL_PORT].value.uint16 = _test_source_port;
    incoming_value[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_ADDRESS].value.uint32 = _test_destination_ipv4_address;
    incoming_value[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_PORT].value.uint16 = _test_destination_port;
    incoming_value[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_PROTOCOL].value.uint8 = _test_protocol;
    incoming_value[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_COMPARTMENT_ID].value.uint32 = _test_compartment_id;
    incoming_value[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_ALE_APP_ID].value.byteBlob = &_test_app_id;
    incoming_value[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_ALE_USER_ID].value.byteBlob = &_test_user_id;

    action = test_cgroup_sock_addr(
        FWPS_LAYER_ALE_CONNECT_REDIRECT_V4, FWPM_LAYER_ALE_CONNECT_REDIRECT_V4, EBPF_DEFAULT_SUBLAYER, incoming_value);
    ebpf_assert(action == FWP_ACTION_PERMIT);

    FWPS_INCOMING_VALUE0 incoming_value2[FWPS_FIELD_ALE_AUTH_CONNECT_V4_MAX] = {};
    incoming_value2[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS].value.uint32 = _test_source_ipv4_address;
    incoming_value2[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT].value.uint16 = _test_source_port;
    incoming_value2[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32 = _test_destination_ipv4_address;
    incoming_value2[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16 = _test_destination_port;
    incoming_value2[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value.uint8 = _test_protocol;
    incoming_value2[FWPS_FIELD_ALE_AUTH_CONNECT_V4_COMPARTMENT_ID].value.uint32 = _test_compartment_id;
    incoming_value2[FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_APP_ID].value.byteBlob = &_test_app_id;
    incoming_value2[FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_USER_ID].value.byteBlob = &_test_user_id;
    incoming_value2[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_INTERFACE].value.uint64 = &_test_interface_luid;

    return test_cgroup_sock_addr(
        FWPS_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V4, EBPF_DEFAULT_SUBLAYER, incoming_value2);
}

// This is used to test the INET6_CONNECT hook.
FWP_ACTION_TYPE
_fwp_engine::test_cgroup_inet6_connect()
{
    FWP_ACTION_TYPE action;
    std::unique_lock l(lock);

    FWPS_INCOMING_VALUE0 incoming_value[FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_MAX] = {};
    incoming_value[FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_LOCAL_ADDRESS].value.byteArray16 = &_test_source_ipv6_address;
    incoming_value[FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_LOCAL_PORT].value.uint16 = _test_source_port;
    incoming_value[FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_REMOTE_ADDRESS].value.byteArray16 =
        &_test_destination_ipv6_address;
    incoming_value[FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_REMOTE_PORT].value.uint16 = _test_destination_port;
    incoming_value[FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_PROTOCOL].value.uint8 = _test_protocol;
    incoming_value[FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_COMPARTMENT_ID].value.uint32 = _test_compartment_id;
    incoming_value[FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_ALE_APP_ID].value.byteBlob = &_test_app_id;
    incoming_value[FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_ALE_USER_ID].value.byteBlob = &_test_user_id;

    action = test_cgroup_sock_addr(
        FWPS_LAYER_ALE_CONNECT_REDIRECT_V6,
        FWPM_LAYER_ALE_CONNECT_REDIRECT_V6,
        EBPF_HOOK_CGROUP_CONNECT_V6_SUBLAYER,
        incoming_value);
    ebpf_assert(action == FWP_ACTION_PERMIT);

    FWPS_INCOMING_VALUE0 incoming_value2[FWPS_FIELD_ALE_AUTH_CONNECT_V6_MAX] = {};
    incoming_value2[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS].value.byteArray16 = &_test_source_ipv6_address;
    incoming_value2[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT].value.uint16 = _test_source_port;
    incoming_value2[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS].value.byteArray16 =
        &_test_destination_ipv6_address;
    incoming_value2[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT].value.uint16 = _test_destination_port;
    incoming_value2[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL].value.uint8 = _test_protocol;
    incoming_value2[FWPS_FIELD_ALE_AUTH_CONNECT_V6_COMPARTMENT_ID].value.uint32 = _test_compartment_id;
    incoming_value2[FWPS_FIELD_ALE_AUTH_CONNECT_V6_ALE_APP_ID].value.byteBlob = &_test_app_id;
    incoming_value2[FWPS_FIELD_ALE_AUTH_CONNECT_V6_ALE_USER_ID].value.byteBlob = &_test_user_id;
    incoming_value2[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_INTERFACE].value.uint64 = &_test_interface_luid;

    return test_cgroup_sock_addr(
        FWPS_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_CONNECT_V6, EBPF_DEFAULT_SUBLAYER, incoming_value2);
}

// This is used to test the SOCK_OPS hook for IPv4 traffic.
FWP_ACTION_TYPE
_fwp_engine::test_sock_ops_v4()
{
    std::unique_lock l(lock);

    FWPS_INCOMING_VALUE0 incoming_value[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_MAX] = {};
    incoming_value[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_ADDRESS].value.uint32 = _test_destination_ipv4_address;
    incoming_value[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_PORT].value.uint16 = _test_destination_port;
    incoming_value[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_ADDRESS].value.uint32 = _test_source_ipv4_address;
    incoming_value[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_PORT].value.uint16 = _test_source_port;
    incoming_value[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_PROTOCOL].value.uint8 = _test_protocol;
    incoming_value[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_COMPARTMENT_ID].value.uint32 = _test_compartment_id;
    incoming_value[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_INTERFACE].value.uint64 = &_test_interface_luid;
    incoming_value[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_ALE_APP_ID].value.byteBlob = &_test_app_id;

    return test_callout(
        FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4, FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4, EBPF_DEFAULT_SUBLAYER, incoming_value);
}

// This is used to test the SOCK_OPS hook for IPv6 traffic.
FWP_ACTION_TYPE
_fwp_engine::test_sock_ops_v6()
{
    std::unique_lock l(lock);

    FWPS_INCOMING_VALUE0 incoming_value[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_MAX] = {};
    incoming_value[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_ADDRESS].value.byteArray16 =
        &_test_destination_ipv6_address;
    incoming_value[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_PORT].value.uint16 = _test_destination_port;
    incoming_value[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_ADDRESS].value.byteArray16 = &_test_source_ipv6_address;
    incoming_value[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_PORT].value.uint16 = _test_source_port;
    incoming_value[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_PROTOCOL].value.uint8 = _test_protocol;
    incoming_value[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_COMPARTMENT_ID].value.uint32 = _test_compartment_id;
    incoming_value[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_INTERFACE].value.uint64 = &_test_interface_luid;
    incoming_value[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_ALE_APP_ID].value.byteBlob = &_test_app_id;

    return test_callout(
        FWPS_LAYER_ALE_FLOW_ESTABLISHED_V6, FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6, EBPF_DEFAULT_SUBLAYER, incoming_value);
}

typedef struct _fwp_injection_handle
{
    ADDRESS_FAMILY address_family;
    uint32_t flags;
} fwp_injection_handle;

static std::unique_ptr<fwp_injection_handle> _injection_handle;

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS FwpmFilterDeleteById0(_In_ HANDLE engine_handle, _In_ uint64_t id)
{
    auto& engine = *reinterpret_cast<_fwp_engine*>(engine_handle);

    if (engine.remove_fwpm_filter(id)) {
        return STATUS_SUCCESS;
    } else {
        return STATUS_INVALID_PARAMETER;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS
    FwpmTransactionBegin0(_In_ _Acquires_lock_(_Curr_) HANDLE engine_handle, _In_ uint32_t flags)
{
    UNREFERENCED_PARAMETER(engine_handle);
    UNREFERENCED_PARAMETER(flags);
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS FwpmFilterAdd0(
    _In_ HANDLE engine_handle,
    _In_ const FWPM_FILTER0* filter,
    _In_opt_ PSECURITY_DESCRIPTOR sd,
    _Out_opt_ uint64_t* id)
{
    UNREFERENCED_PARAMETER(sd);

    auto& engine = *reinterpret_cast<_fwp_engine*>(engine_handle);

    auto id_returned = engine.add_fwpm_filter(filter);

    if (id) {
        *id = id_returned;
    }

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS FwpmTransactionCommit0(_In_ _Releases_lock_(_Curr_) HANDLE engine_handle)
{
    UNREFERENCED_PARAMETER(engine_handle);
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS FwpmTransactionAbort0(_In_ _Releases_lock_(_Curr_) HANDLE engine_handle)
{
    UNREFERENCED_PARAMETER(engine_handle);
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS
    FwpsCalloutRegister3(_Inout_ void* device_object, _In_ const FWPS_CALLOUT3* callout, _Out_opt_ uint32_t* callout_id)
{
    UNREFERENCED_PARAMETER(device_object);

    auto& engine = *_fwp_engine::get()->get();

    auto id_returned = engine.register_fwps_callout(callout);

    if (callout_id) {
        *callout_id = id_returned;
    }

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS FwpmCalloutAdd0(
    _In_ HANDLE engine_handle,
    _In_ const FWPM_CALLOUT0* callout,
    _In_opt_ PSECURITY_DESCRIPTOR sd,
    _Out_opt_ uint32_t* id)
{
    auto& engine = *reinterpret_cast<_fwp_engine*>(engine_handle);

    auto id_returned = engine.add_fwpm_callout(callout);

    if (id) {
        *id = id_returned;
    }
    UNREFERENCED_PARAMETER(sd);
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS FwpsCalloutUnregisterById0(_In_ const uint32_t callout_id)
{
    auto& engine = *_fwp_engine::get()->get();

    if (engine.remove_fwps_callout(callout_id)) {
        return STATUS_SUCCESS;
    } else {
        return STATUS_INVALID_PARAMETER;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS FwpmEngineOpen0(
    _In_opt_ const wchar_t* server_name,
    _In_ uint32_t authn_service,
    _In_opt_ SEC_WINNT_AUTH_IDENTITY_W* auth_identity,
    _In_opt_ const FWPM_SESSION0* session,
    _Out_ HANDLE* engine_handle)
{
    UNREFERENCED_PARAMETER(server_name);
    UNREFERENCED_PARAMETER(authn_service);
    UNREFERENCED_PARAMETER(auth_identity);
    UNREFERENCED_PARAMETER(session);

    *engine_handle = _fwp_engine::get()->get();
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS
    FwpmSubLayerAdd0(_In_ HANDLE engine_handle, _In_ const FWPM_SUBLAYER0* sub_layer, _In_opt_ PSECURITY_DESCRIPTOR sd)
{
    UNREFERENCED_PARAMETER(sd);
    auto& engine = *reinterpret_cast<_fwp_engine*>(engine_handle);

    engine.add_fwpm_sub_layer(sub_layer);

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS FwpmEngineClose0(_Inout_ HANDLE engine_handle)
{
    if (engine_handle != _fwp_engine::get()->get()) {
        return STATUS_INVALID_PARAMETER;
    } else {
        return STATUS_SUCCESS;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS FwpsInjectionHandleCreate0(
    _In_opt_ ADDRESS_FAMILY address_family, _In_ uint32_t flags, _Out_ HANDLE* injection_handle)
{
    _injection_handle = std::make_unique<_fwp_injection_handle>(address_family, flags);
    *injection_handle = _injection_handle.get();

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS FwpsInjectionHandleDestroy0(_In_ HANDLE injection_handle)
{
    if (injection_handle != _injection_handle.get()) {
        return STATUS_INVALID_PARAMETER;
    } else {
        _injection_handle.reset();
        return STATUS_SUCCESS;
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL) NTSTATUS
    FwpsFlowRemoveContext0(_In_ uint64_t flow_id, _In_ UINT16 layer_id, _In_ uint32_t callout_id)
{
    UNREFERENCED_PARAMETER(flow_id);
    UNREFERENCED_PARAMETER(layer_id);
    UNREFERENCED_PARAMETER(callout_id);
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL) NTSTATUS FwpsFlowAssociateContext0(
    _In_ uint64_t flow_id, _In_ UINT16 layer_id, _In_ uint32_t callout_id, _In_ uint64_t flowContext)
{
    UNREFERENCED_PARAMETER(flow_id);
    UNREFERENCED_PARAMETER(layer_id);
    UNREFERENCED_PARAMETER(callout_id);
    UNREFERENCED_PARAMETER(flowContext);
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL) NTSTATUS FwpsAllocateNetBufferAndNetBufferList0(
    _In_ NDIS_HANDLE pool_handle,
    _In_ uint16_t context_size,
    _In_ uint16_t context_backfill,
    _In_opt_ MDL* mdl_chain,
    _In_ unsigned long data_offset,
    _In_ size_t data_length,
    _Outptr_ NET_BUFFER_LIST** net_buffer_list)
{
    NTSTATUS status;
    NET_BUFFER_LIST* new_net_buffer_list = NULL;

    UNREFERENCED_PARAMETER(pool_handle);
    UNREFERENCED_PARAMETER(context_size);
    UNREFERENCED_PARAMETER(context_backfill);
    UNREFERENCED_PARAMETER(data_offset);

    new_net_buffer_list =
        (NET_BUFFER_LIST*)(ExAllocatePoolUninitialized(NonPagedPool, sizeof(NET_BUFFER_LIST), '1PWF'));
    if (!new_net_buffer_list) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Done;
    }

    RtlZeroMemory(new_net_buffer_list, sizeof(NET_BUFFER_LIST));

    new_net_buffer_list->FirstNetBuffer =
        (NET_BUFFER*)(ExAllocatePoolUninitialized(NonPagedPool, sizeof(NET_BUFFER), '2PWF'));
    if (!new_net_buffer_list->FirstNetBuffer) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Done;
    }

    RtlZeroMemory(new_net_buffer_list->FirstNetBuffer, sizeof(NET_BUFFER));

    new_net_buffer_list->FirstNetBuffer->MdlChain = mdl_chain;
    new_net_buffer_list->FirstNetBuffer->DataLength = (unsigned long)data_length;

    *net_buffer_list = new_net_buffer_list;
    new_net_buffer_list = NULL;
    status = STATUS_SUCCESS;

Done:
    if (new_net_buffer_list) {
        FwpsFreeNetBufferList0(new_net_buffer_list);
    }
    return status;
}

_IRQL_requires_max_(DISPATCH_LEVEL) void FwpsFreeNetBufferList0(_In_ NET_BUFFER_LIST* net_buffer_list)
{
    if (!net_buffer_list) {
        return;
    }

    if (net_buffer_list->FirstNetBuffer) {
        ExFreePool(net_buffer_list->FirstNetBuffer);
    }

    ExFreePool(net_buffer_list);
}

_IRQL_requires_min_(PASSIVE_LEVEL) _IRQL_requires_max_(DISPATCH_LEVEL) _Must_inspect_result_ NTSTATUS
    FwpsInjectMacReceiveAsync0(
        _In_ HANDLE injection_handle,
        _In_opt_ HANDLE injection_context,
        _In_ uint32_t flags,
        _In_ UINT16 layer_id,
        _In_ IF_INDEX interface_index,
        _In_ NDIS_PORT_NUMBER ndis_port_number,
        _Inout_ NET_BUFFER_LIST* net_buffer_lists,
        _In_ FWPS_INJECT_COMPLETE completion_function,
        _In_opt_ HANDLE completion_context)
{
    UNREFERENCED_PARAMETER(injection_handle);
    UNREFERENCED_PARAMETER(injection_context);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(layer_id);
    UNREFERENCED_PARAMETER(interface_index);
    UNREFERENCED_PARAMETER(ndis_port_number);
    UNREFERENCED_PARAMETER(net_buffer_lists);
    UNREFERENCED_PARAMETER(completion_function);
    UNREFERENCED_PARAMETER(completion_context);
    return STATUS_NOT_IMPLEMENTED;
}

_IRQL_requires_max_(DISPATCH_LEVEL) void FwpsFreeCloneNetBufferList0(
    _In_ NET_BUFFER_LIST* net_buffer_list, _In_ unsigned long free_clone_flags)
{
    UNREFERENCED_PARAMETER(net_buffer_list);
    UNREFERENCED_PARAMETER(free_clone_flags);
}

_IRQL_requires_max_(DISPATCH_LEVEL) NTSTATUS FwpsAllocateCloneNetBufferList0(
    _Inout_ NET_BUFFER_LIST* original_net_buffer_list,
    _In_opt_ NDIS_HANDLE net_buffer_list_pool_handle,
    _In_opt_ NDIS_HANDLE net_buffer_pool_handle,
    _In_ unsigned long allocate_clone_flags,
    _Outptr_ NET_BUFFER_LIST** net_buffer_list)
{
    UNREFERENCED_PARAMETER(original_net_buffer_list);
    UNREFERENCED_PARAMETER(net_buffer_list_pool_handle);
    UNREFERENCED_PARAMETER(net_buffer_pool_handle);
    UNREFERENCED_PARAMETER(net_buffer_pool_handle);
    UNREFERENCED_PARAMETER(allocate_clone_flags);
    UNREFERENCED_PARAMETER(net_buffer_list);
    return STATUS_NOT_IMPLEMENTED;
}

_IRQL_requires_min_(PASSIVE_LEVEL) _IRQL_requires_max_(DISPATCH_LEVEL) _Must_inspect_result_ NTSTATUS
    FwpsInjectMacSendAsync0(
        _In_ HANDLE injection_handle,
        _In_opt_ HANDLE injection_context,
        _In_ uint32_t flags,
        _In_ UINT16 layer_id,
        _In_ IF_INDEX interface_index,
        _In_ NDIS_PORT_NUMBER ndis_port_number,
        _Inout_ NET_BUFFER_LIST* net_buffer_lists,
        _In_ FWPS_INJECT_COMPLETE completion_function,
        _In_opt_ HANDLE completion_context)
{
    UNREFERENCED_PARAMETER(injection_handle);
    UNREFERENCED_PARAMETER(injection_context);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(layer_id);
    UNREFERENCED_PARAMETER(interface_index);
    UNREFERENCED_PARAMETER(ndis_port_number);
    UNREFERENCED_PARAMETER(net_buffer_lists);
    UNREFERENCED_PARAMETER(completion_function);
    UNREFERENCED_PARAMETER(completion_context);
    return STATUS_NOT_IMPLEMENTED;
}

_IRQL_requires_max_(DISPATCH_LEVEL) NTSTATUS NTAPI FwpsAcquireWritableLayerDataPointer0(
    _In_ UINT64 classifyHandle,
    _In_ UINT64 filterId,
    _In_ UINT32 flags,
    _Out_ PVOID* writableLayerData,
    _Inout_opt_ FWPS_CLASSIFY_OUT0* classifyOut)
{
    UNREFERENCED_PARAMETER(classifyHandle);
    UNREFERENCED_PARAMETER(filterId);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(classifyOut);

    *writableLayerData = NULL;

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL) NTSTATUS NTAPI
    FwpsAcquireClassifyHandle0(_In_ void* classifyContext, _In_ UINT32 flags, _Out_ UINT64* classifyHandle)
{
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(classifyHandle);

    *classifyHandle = 0;

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL) void NTAPI FwpsReleaseClassifyHandle0(_In_ UINT64 classifyHandle)
{
    UNREFERENCED_PARAMETER(classifyHandle);
}

_IRQL_requires_max_(DISPATCH_LEVEL) void NTAPI
    FwpsApplyModifiedLayerData0(_In_ UINT64 classifyHandle, _In_ PVOID modifiedLayerData, _In_ UINT32 flags)
{
    UNREFERENCED_PARAMETER(classifyHandle);
    UNREFERENCED_PARAMETER(modifiedLayerData);
    UNREFERENCED_PARAMETER(flags);
}

_IRQL_requires_(PASSIVE_LEVEL) NTSTATUS NTAPI
    FwpsRedirectHandleCreate0(_In_ const GUID* providerGuid, _Reserved_ UINT32 flags, _Out_ HANDLE* redirectHandle)
{
    UNREFERENCED_PARAMETER(providerGuid);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(redirectHandle);

    *redirectHandle = 0;

    return STATUS_SUCCESS;
}

_IRQL_requires_min_(PASSIVE_LEVEL) _IRQL_requires_max_(DISPATCH_LEVEL) FWPS_CONNECTION_REDIRECT_STATE NTAPI
    FwpsQueryConnectionRedirectState0(
        _In_ HANDLE redirectRecords, _In_ HANDLE redirectHandle, _Outptr_opt_result_maybenull_ void** redirectContext)
{
    UNREFERENCED_PARAMETER(redirectRecords);
    UNREFERENCED_PARAMETER(redirectHandle);

    if (redirectContext) {
        *redirectContext = NULL;
    }

    return FWPS_CONNECTION_NOT_REDIRECTED;
}
