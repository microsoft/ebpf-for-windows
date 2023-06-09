// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/**
 * @file
 * @brief This file implements the hook for the CGROUP_SOCK_ADDR program type and associated attach types, on eBPF for
 * Windows.
 */

#include "ebpf_store_helper.h"
#include "net_ebpf_ext_sock_addr.h"

#define TARGET_PROCESS_ID 1234
#define EXPIRY_TIME 60000 // 60 seconds in ms.
#define CONVERT_100NS_UNITS_TO_MS(x) ((x) / 10000)

#define NET_EBPF_EXT_SOCK_ADDR_CLASSIFY_MESSAGE "NetEbpfExtSockAddrClassify"

#define NET_EBPF_EXT_LOG_SOCK_ADDR_CLASSIFY_IPV4(                                                              \
    trace_level, message, handle, protocol, source_ip, source_port, destination_ip, destination_port, verdict) \
    TraceLoggingWrite(                                                                                         \
        net_ebpf_ext_tracelog_provider,                                                                        \
        NET_EBPF_EXT_SOCK_ADDR_CLASSIFY_MESSAGE,                                                               \
        TraceLoggingLevel(trace_level),                                                                        \
        TraceLoggingKeyword(NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR),                                          \
        TraceLoggingString((message), "message"),                                                              \
        TraceLoggingUInt64((handle), "transport_endpoint_handle"),                                             \
        TraceLoggingUInt64((protocol), "protocol"),                                                            \
        TraceLoggingIPv4Address((source_ip), "source_ip"),                                                     \
        TraceLoggingUInt16((source_port), "source_port"),                                                      \
        TraceLoggingIPv4Address((destination_ip), "destination_ip"),                                           \
        TraceLoggingUInt16((destination_port), "destination_port"),                                            \
        TraceLoggingUInt32((verdict), "verdict"));

#define NET_EBPF_EXT_LOG_SOCK_ADDR_CLASSIFY_IPV6(                                                              \
    trace_level, message, handle, protocol, source_ip, source_port, destination_ip, destination_port, verdict) \
    TraceLoggingWrite(                                                                                         \
        net_ebpf_ext_tracelog_provider,                                                                        \
        NET_EBPF_EXT_SOCK_ADDR_CLASSIFY_MESSAGE,                                                               \
        TraceLoggingLevel(trace_level),                                                                        \
        TraceLoggingKeyword(NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR),                                          \
        TraceLoggingString((message), "message"),                                                              \
        TraceLoggingUInt64((handle), "transport_endpoint_handle"),                                             \
        TraceLoggingUInt64((protocol), "protocol"),                                                            \
        TraceLoggingIPv6Address((source_ip), "source_ip"),                                                     \
        TraceLoggingUInt16((source_port), "source_port"),                                                      \
        TraceLoggingIPv6Address((destination_ip), "destination_ip"),                                           \
        TraceLoggingUInt16((destination_port), "destination_port"),                                            \
        TraceLoggingUInt32((verdict), "verdict"));

#define NET_EBPF_EXT_SOCK_ADDR_REDIRECT_MESSAGE "NetEbpfExtSockAddrRedirect"

#define NET_EBPF_EXT_LOG_SOCK_ADDR_REDIRECT_CLASSIFY_IPV4(            \
    message,                                                          \
    handle,                                                           \
    protocol,                                                         \
    source_ip,                                                        \
    source_port,                                                      \
    destination_ip,                                                   \
    destination_port,                                                 \
    redirected_ip,                                                    \
    redirected_port,                                                  \
    verdict)                                                          \
    TraceLoggingWrite(                                                \
        net_ebpf_ext_tracelog_provider,                               \
        NET_EBPF_EXT_SOCK_ADDR_REDIRECT_MESSAGE,                      \
        TraceLoggingLevel(NET_EBPF_EXT_TRACELOG_LEVEL_INFO),          \
        TraceLoggingKeyword(NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR), \
        TraceLoggingString((message), "message"),                     \
        TraceLoggingUInt64((handle), "transport_endpoint_handle"),    \
        TraceLoggingUInt64((protocol), "protocol"),                   \
        TraceLoggingIPv4Address((source_ip), "source_ip"),            \
        TraceLoggingUInt16((source_port), "source_port"),             \
        TraceLoggingIPv4Address((destination_ip), "destination_ip"),  \
        TraceLoggingUInt16((destination_port), "destination_port"),   \
        TraceLoggingIPv4Address((redirected_ip), "redirected_ip"),    \
        TraceLoggingUInt16((redirected_port), "redirected_port"),     \
        TraceLoggingUInt64((verdict), "verdict"));

#define NET_EBPF_EXT_LOG_SOCK_ADDR_REDIRECT_CLASSIFY_IPV6(            \
    message,                                                          \
    handle,                                                           \
    protocol,                                                         \
    source_ip,                                                        \
    source_port,                                                      \
    destination_ip,                                                   \
    destination_port,                                                 \
    redirected_ip,                                                    \
    redirected_port,                                                  \
    verdict)                                                          \
    TraceLoggingWrite(                                                \
        net_ebpf_ext_tracelog_provider,                               \
        NET_EBPF_EXT_SOCK_ADDR_REDIRECT_MESSAGE,                      \
        TraceLoggingLevel(NET_EBPF_EXT_TRACELOG_LEVEL_INFO),          \
        TraceLoggingKeyword(NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR), \
        TraceLoggingString((message), "message"),                     \
        TraceLoggingUInt64((handle), "transport_endpoint_handle"),    \
        TraceLoggingUInt64((protocol), "protocol"),                   \
        TraceLoggingIPv6Address((source_ip), "source_ip"),            \
        TraceLoggingUInt16((source_port), "source_port"),             \
        TraceLoggingIPv6Address((destination_ip), "destination_ip"),  \
        TraceLoggingUInt16((destination_port), "destination_port"),   \
        TraceLoggingIPv6Address((redirected_ip), "redirected_ip"),    \
        TraceLoggingUInt16((redirected_port), "redirected_port"),     \
        TraceLoggingUInt64((verdict), "verdict"));

#define DEFINE_SOCK_ADDR_CLASSIFY_LOG_FUNCTION(family)                  \
    static void _net_ebpf_ext_log_sock_addr_classify_v##family##(       \
        _In_z_ const char* message,                                     \
        uint64_t transport_endpoint_handle,                             \
        _In_ const bpf_sock_addr_t* original_context,                   \
        _In_opt_ const bpf_sock_addr_t* redirected_context,             \
        uint32_t verdict)                                               \
    {                                                                   \
        if (redirected_context != NULL) {                               \
            NET_EBPF_EXT_LOG_SOCK_ADDR_REDIRECT_CLASSIFY_IPV##family##( \
                message,                                                \
                transport_endpoint_handle,                              \
                original_context->protocol,                             \
                original_context->msg_src_ip##family##,                 \
                ntohs(original_context->msg_src_port),                  \
                original_context->user_ip##family##,                    \
                ntohs(original_context->user_port),                     \
                redirected_context->user_ip##family##,                  \
                ntohs(redirected_context->user_port),                   \
                verdict);                                               \
        } else {                                                        \
            if (verdict == BPF_SOCK_ADDR_VERDICT_REJECT) {              \
                NET_EBPF_EXT_LOG_SOCK_ADDR_CLASSIFY_IPV##family##(      \
                    NET_EBPF_EXT_TRACELOG_LEVEL_INFO,                   \
                    message,                                            \
                    transport_endpoint_handle,                          \
                    original_context->protocol,                         \
                    original_context->msg_src_ip##family##,             \
                    ntohs(original_context->msg_src_port),              \
                    original_context->user_ip##family##,                \
                    ntohs(original_context->user_port),                 \
                    verdict);                                           \
            } else {                                                    \
                NET_EBPF_EXT_LOG_SOCK_ADDR_CLASSIFY_IPV##family##(      \
                    NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,                \
                    message,                                            \
                    transport_endpoint_handle,                          \
                    original_context->protocol,                         \
                    original_context->msg_src_ip##family##,             \
                    ntohs(original_context->msg_src_port),              \
                    original_context->user_ip##family##,                \
                    ntohs(original_context->user_port),                 \
                    verdict);                                           \
            }                                                           \
        }                                                               \
    }

DEFINE_SOCK_ADDR_CLASSIFY_LOG_FUNCTION(4)
DEFINE_SOCK_ADDR_CLASSIFY_LOG_FUNCTION(6)

static void
_net_ebpf_ext_log_sock_addr_classify(
    _In_z_ const char* message,
    uint64_t transport_endpoint_handle,
    _In_ const bpf_sock_addr_t* original_context,
    _In_opt_ const bpf_sock_addr_t* redirected_context,
    uint32_t verdict)
{
    if (TraceLoggingProviderEnabled(net_ebpf_ext_tracelog_provider, 0, NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR)) {
        if (original_context->family == AF_INET) {
            _net_ebpf_ext_log_sock_addr_classify_v4(
                message, transport_endpoint_handle, original_context, redirected_context, verdict);
        } else {
            _net_ebpf_ext_log_sock_addr_classify_v6(
                message, transport_endpoint_handle, original_context, redirected_context, verdict);
        }
    }
}

typedef struct _net_ebpf_bpf_sock_addr
{
    bpf_sock_addr_t base;
    TOKEN_ACCESS_INFORMATION* access_information;
    uint64_t process_id;
    uint32_t flags;
} net_ebpf_sock_addr_t;

/**
 * Connection context info does not contain the source IP address because
 * the source IP address is not always available at connect_redirect layer.
 * Source port is however available and included below for a stricter check.
 */
typedef struct _net_ebpf_ext_connect_context_address_info
{
    uint32_t family;
    union
    {
        uint32_t ipv4;
        uint32_t ipv6[4];
    } destination_ip;
    uint16_t destination_port;
    uint16_t source_port;
} net_ebpf_ext_connect_context_address_info_t;

typedef struct _net_ebpf_extension_connection_context
{
    uint64_t transport_endpoint_handle;
    net_ebpf_ext_connect_context_address_info_t address_info;
    uint32_t compartment_id;
    uint16_t protocol;
    uint64_t timestamp;
    LIST_ENTRY list_entry;
} net_ebpf_extension_connection_context_t;

typedef struct _net_ebpf_ext_sock_addr_statistics
{
    volatile long permit_connection_count;
    volatile long redirect_connection_count;
    volatile long block_connection_count;
} net_ebpf_ext_sock_addr_statistics_t;

static net_ebpf_ext_sock_addr_statistics_t _net_ebpf_ext_statistics;

static EX_SPIN_LOCK _net_ebpf_ext_sock_addr_lock;
// TODO: Issue #1675 (Use hash table to store connection contexts in netebpfext)
_Guarded_by_(_net_ebpf_ext_sock_addr_lock) static LIST_ENTRY _net_ebpf_ext_connect_context_list;
static uint32_t _net_ebpf_ext_connect_context_count = 0;

static SECURITY_DESCRIPTOR* _net_ebpf_ext_security_descriptor_admin = NULL;
static ACL* _net_ebpf_ext_dacl_admin = NULL;
static GENERIC_MAPPING _net_ebpf_ext_generic_mapping = {0};

//
// sock_addr helper functions.
//
static uint32_t
_get_process_id()
{
    return (uint32_t)(uintptr_t)PsGetCurrentProcessId();
}

static uint32_t
_get_thread_id()
{
    return (uint32_t)(uintptr_t)PsGetCurrentThreadId();
}

static uint64_t
_ebpf_sock_addr_get_current_pid_tgid(_In_ const bpf_sock_addr_t* ctx)
{
    net_ebpf_sock_addr_t* sock_addr_ctx = CONTAINING_RECORD(ctx, net_ebpf_sock_addr_t, base);
    return (sock_addr_ctx->process_id << 32 | _get_thread_id());
}

static uint64_t
_ebpf_sock_addr_get_current_logon_id(_In_ const bpf_sock_addr_t* ctx)
{
    uint64_t logon_id = 0;
    net_ebpf_sock_addr_t* sock_addr_ctx = CONTAINING_RECORD(ctx, net_ebpf_sock_addr_t, base);
    logon_id = *(uint64_t*)(&(sock_addr_ctx->access_information->AuthenticationId));

    return logon_id;
}

_IRQL_requires_max_(DISPATCH_LEVEL) static NTSTATUS _perform_access_check(
    _In_ SECURITY_DESCRIPTOR* security_descriptor,
    _In_ TOKEN_ACCESS_INFORMATION* access_information,
    _Out_ BOOLEAN* access_allowed)
{
    ACCESS_MASK granted_access;
    NTSTATUS status;

    *access_allowed = SeAccessCheckFromState(
        security_descriptor,
        access_information,
        NULL,
        FILE_WRITE_ACCESS,
        0,
        NULL,
        &_net_ebpf_ext_generic_mapping,
        UserMode,
        &granted_access,
        &status);

    // Not tracing error as this function can be called in hot path.
    // Non-success status means access not granted, and does not mean failure.
    return status;
}

static int32_t
_ebpf_sock_addr_is_current_admin(_In_ const bpf_sock_addr_t* ctx)
{
    NTSTATUS status;
    BOOLEAN access_allowed = FALSE;
    net_ebpf_sock_addr_t* sock_addr_ctx = NULL;
    int32_t is_admin = 0;

    sock_addr_ctx = CONTAINING_RECORD(ctx, net_ebpf_sock_addr_t, base);
    status = _perform_access_check(
        _net_ebpf_ext_security_descriptor_admin, sock_addr_ctx->access_information, &access_allowed);

    if (!NT_SUCCESS(status)) {
        return is_admin;
    }

    if (access_allowed) {
        is_admin = 1;
    }

    return is_admin;
}

//
// WFP filter related types & globals for SOCK_ADDR hook.
//

const ebpf_attach_type_t* _net_ebpf_extension_sock_addr_attach_types[] = {
    &EBPF_ATTACH_TYPE_CGROUP_INET4_CONNECT,
    &EBPF_ATTACH_TYPE_CGROUP_INET4_RECV_ACCEPT,
    &EBPF_ATTACH_TYPE_CGROUP_INET6_CONNECT,
    &EBPF_ATTACH_TYPE_CGROUP_INET6_RECV_ACCEPT};

const uint32_t _net_ebpf_extension_sock_addr_bpf_attach_types[] = {
    BPF_CGROUP_INET4_CONNECT, BPF_CGROUP_INET4_RECV_ACCEPT, BPF_CGROUP_INET6_CONNECT, BPF_CGROUP_INET6_RECV_ACCEPT};

#define NET_EBPF_SOCK_ADDR_HOOK_PROVIDER_COUNT EBPF_COUNT_OF(_net_ebpf_extension_sock_addr_attach_types)

net_ebpf_extension_wfp_filter_parameters_t _cgroup_inet4_connect_filter_parameters[] = {
    {&FWPM_LAYER_ALE_AUTH_CONNECT_V4,
     NULL, // Default sublayer.
     &EBPF_HOOK_ALE_AUTH_CONNECT_V4_CALLOUT,
     L"net eBPF sock_addr hook",
     L"net eBPF sock_addr hook WFP filter"},

    {&FWPM_LAYER_ALE_CONNECT_REDIRECT_V4,
     NULL, // Default sublayer.
     &EBPF_HOOK_ALE_CONNECT_REDIRECT_V4_CALLOUT,
     L"net eBPF sock_addr hook",
     L"net eBPF sock_addr hook WFP filter"},

    {&FWPM_LAYER_ALE_CONNECT_REDIRECT_V6,
     &EBPF_HOOK_CGROUP_CONNECT_V4_SUBLAYER,
     &EBPF_HOOK_ALE_CONNECT_REDIRECT_V6_CALLOUT,
     L"net eBPF sock_addr hook",
     L"net eBPF sock_addr hook WFP filter"}};

net_ebpf_extension_wfp_filter_parameters_t _cgroup_inet6_connect_filter_parameters[] = {
    {&FWPM_LAYER_ALE_AUTH_CONNECT_V6,
     NULL, // Default sublayer.
     &EBPF_HOOK_ALE_AUTH_CONNECT_V6_CALLOUT,
     L"net eBPF sock_addr hook",
     L"net eBPF sock_addr hook WFP filter"},

    {&FWPM_LAYER_ALE_CONNECT_REDIRECT_V6,
     &EBPF_HOOK_CGROUP_CONNECT_V6_SUBLAYER,
     &EBPF_HOOK_ALE_CONNECT_REDIRECT_V6_CALLOUT,
     L"net eBPF sock_addr hook",
     L"net eBPF sock_addr hook WFP filter"}};

net_ebpf_extension_wfp_filter_parameters_t _cgroup_inet4_recv_accept_filter_parameters[] = {
    {&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
     NULL, // Default sublayer.
     &EBPF_HOOK_ALE_AUTH_RECV_ACCEPT_V4_CALLOUT,
     L"net eBPF sock_addr hook",
     L"net eBPF sock_addr hook WFP filter"}};

net_ebpf_extension_wfp_filter_parameters_t _cgroup_inet6_recv_accept_filter_parameters[] = {
    {&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
     NULL,
     &EBPF_HOOK_ALE_AUTH_RECV_ACCEPT_V6_CALLOUT,
     L"net eBPF sock_addr hook",
     L"net eBPF sock_addr hook WFP filter"}};

const net_ebpf_extension_wfp_filter_parameters_array_t _net_ebpf_extension_sock_addr_wfp_filter_parameters[] = {
    {&EBPF_ATTACH_TYPE_CGROUP_INET4_CONNECT,
     EBPF_COUNT_OF(_cgroup_inet4_connect_filter_parameters),
     &_cgroup_inet4_connect_filter_parameters[0]},
    {&EBPF_ATTACH_TYPE_CGROUP_INET4_RECV_ACCEPT,
     EBPF_COUNT_OF(_cgroup_inet4_recv_accept_filter_parameters),
     &_cgroup_inet4_recv_accept_filter_parameters[0]},
    {&EBPF_ATTACH_TYPE_CGROUP_INET6_CONNECT,
     EBPF_COUNT_OF(_cgroup_inet6_connect_filter_parameters),
     &_cgroup_inet6_connect_filter_parameters[0]},
    {&EBPF_ATTACH_TYPE_CGROUP_INET4_RECV_ACCEPT,
     EBPF_COUNT_OF(_cgroup_inet6_recv_accept_filter_parameters),
     &_cgroup_inet6_recv_accept_filter_parameters[0]},
};

typedef struct _net_ebpf_extension_sock_addr_wfp_filter_context
{
    net_ebpf_extension_wfp_filter_context_t base;
    HANDLE redirect_handle;
    uint32_t compartment_id;
    BOOLEAN v4_attach_type;
} net_ebpf_extension_sock_addr_wfp_filter_context_t;

static ebpf_result_t
_ebpf_sock_addr_context_create(
    _In_reads_bytes_opt_(data_size_in) const uint8_t* data_in,
    size_t data_size_in,
    _In_reads_bytes_opt_(context_size_in) const uint8_t* context_in,
    size_t context_size_in,
    _Outptr_ void** context);

static void
_ebpf_sock_addr_context_destroy(
    _In_opt_ void* context,
    _Out_writes_bytes_to_(*data_size_out, *data_size_out) uint8_t* data_out,
    _Inout_ size_t* data_size_out,
    _Out_writes_bytes_to_(*context_size_out, *context_size_out) uint8_t* context_out,
    _Inout_ size_t* context_size_out);

//
// SOCK_ADDR Program Information NPI Provider.
//

static const void* _ebpf_sock_addr_specific_helper_functions[] = {(void*)_ebpf_sock_addr_get_current_pid_tgid};

static ebpf_helper_function_addresses_t _ebpf_sock_addr_specific_helper_function_address_table = {
    EBPF_COUNT_OF(_ebpf_sock_addr_specific_helper_functions), (uint64_t*)_ebpf_sock_addr_specific_helper_functions};

static const void* _ebpf_sock_addr_global_helper_functions[] = {
    (void*)_ebpf_sock_addr_get_current_logon_id, (void*)_ebpf_sock_addr_is_current_admin};

static ebpf_helper_function_addresses_t _ebpf_sock_addr_global_helper_function_address_table = {
    EBPF_COUNT_OF(_ebpf_sock_addr_global_helper_functions), (uint64_t*)_ebpf_sock_addr_global_helper_functions};

static ebpf_program_data_t _ebpf_sock_addr_program_data = {
    .program_info = &_ebpf_sock_addr_program_info,
    .program_type_specific_helper_function_addresses = &_ebpf_sock_addr_specific_helper_function_address_table,
    .global_helper_function_addresses = &_ebpf_sock_addr_global_helper_function_address_table,
    .context_create = &_ebpf_sock_addr_context_create,
    .context_destroy = &_ebpf_sock_addr_context_destroy};

static ebpf_extension_data_t _ebpf_sock_addr_program_info_provider_data = {
    NET_EBPF_EXTENSION_NPI_PROVIDER_VERSION, sizeof(_ebpf_sock_addr_program_data), &_ebpf_sock_addr_program_data};

NPI_MODULEID DECLSPEC_SELECTANY _ebpf_sock_addr_program_info_provider_moduleid = {sizeof(NPI_MODULEID), MIT_GUID, {0}};

static net_ebpf_extension_program_info_provider_t* _ebpf_sock_addr_program_info_provider_context = NULL;

//
// SOCK_ADDR Hook NPI Provider.
//

ebpf_attach_provider_data_t _net_ebpf_sock_addr_hook_provider_data[NET_EBPF_SOCK_ADDR_HOOK_PROVIDER_COUNT] = {0};
ebpf_extension_data_t _net_ebpf_extension_sock_addr_hook_provider_data[NET_EBPF_SOCK_ADDR_HOOK_PROVIDER_COUNT] = {0};
NPI_MODULEID DECLSPEC_SELECTANY _ebpf_sock_addr_hook_provider_moduleid[NET_EBPF_SOCK_ADDR_HOOK_PROVIDER_COUNT] = {0};

static net_ebpf_extension_hook_provider_t*
    _ebpf_sock_addr_hook_provider_context[NET_EBPF_SOCK_ADDR_HOOK_PROVIDER_COUNT] = {0};

//
// NMR Registration Helper Routines.
//

static ebpf_result_t
_net_ebpf_extension_sock_addr_on_client_attach(
    _In_ const net_ebpf_extension_hook_client_t* attaching_client,
    _In_ const net_ebpf_extension_hook_provider_t* provider_context)
{
    NTSTATUS status;
    ebpf_result_t result = EBPF_SUCCESS;
    const ebpf_extension_data_t* client_data = net_ebpf_extension_hook_client_get_client_data(attaching_client);
    uint32_t compartment_id;
    uint32_t wild_card_compartment_id = UNSPECIFIED_COMPARTMENT_ID;
    net_ebpf_extension_wfp_filter_parameters_array_t* filter_parameters_array = NULL;
    FWPM_FILTER_CONDITION condition = {0};
    net_ebpf_extension_sock_addr_wfp_filter_context_t* filter_context = NULL;

    NET_EBPF_EXT_LOG_ENTRY();

    // SOCK_ADDR hook clients must always provide data.
    if (client_data == NULL) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    if (client_data->size > 0) {
        if ((client_data->size != sizeof(uint32_t)) || (client_data->data == NULL)) {
            result = EBPF_INVALID_ARGUMENT;
            goto Exit;
        }
        compartment_id = *(uint32_t*)client_data->data;
    } else {
        // If the client did not specify any attach parameters, we treat that as a wildcard compartment id.
        compartment_id = wild_card_compartment_id;
    }

    result = net_ebpf_extension_hook_check_attach_parameter(
        sizeof(compartment_id),
        &compartment_id,
        &wild_card_compartment_id,
        (net_ebpf_extension_hook_provider_t*)provider_context);
    NET_EBPF_EXT_BAIL_ON_ERROR_RESULT(result);

    if (client_data->data != NULL) {
        compartment_id = *(uint32_t*)client_data->data;
    }

    // Set compartment id (if not UNSPECIFIED_COMPARTMENT_ID) as WFP filter condition.
    if (compartment_id != UNSPECIFIED_COMPARTMENT_ID) {
        condition.fieldKey = FWPM_CONDITION_COMPARTMENT_ID;
        condition.matchType = FWP_MATCH_EQUAL;
        condition.conditionValue.type = FWP_UINT32;
        condition.conditionValue.uint32 = compartment_id;
    }

    result = net_ebpf_extension_wfp_filter_context_create(
        sizeof(net_ebpf_extension_sock_addr_wfp_filter_context_t),
        attaching_client,
        (net_ebpf_extension_wfp_filter_context_t**)&filter_context);
    NET_EBPF_EXT_BAIL_ON_ERROR_RESULT(result);

    filter_context->redirect_handle = NULL;
    filter_context->compartment_id = compartment_id;

    // Get the WFP filter parameters for this hook type.
    filter_parameters_array =
        (net_ebpf_extension_wfp_filter_parameters_array_t*)net_ebpf_extension_hook_provider_get_custom_data(
            provider_context);
    ASSERT(filter_parameters_array != NULL);
    filter_context->base.filter_ids_count = filter_parameters_array->count;

    // Special case of connect_redirect. If the attach type is v4, set v4_attach_type in the filter
    // context to TRUE.
    if (memcmp(filter_parameters_array->attach_type, &EBPF_ATTACH_TYPE_CGROUP_INET4_CONNECT, sizeof(GUID)) == 0) {
        filter_context->v4_attach_type = TRUE;
    }

    // Allocate redirect handle for this filter context, only in the case of INET*_CONNECT attach types.
    if (memcmp(filter_parameters_array->attach_type, &EBPF_ATTACH_TYPE_CGROUP_INET4_CONNECT, sizeof(GUID)) == 0 ||
        memcmp(filter_parameters_array->attach_type, &EBPF_ATTACH_TYPE_CGROUP_INET6_CONNECT, sizeof(GUID)) == 0) {
        status =
            FwpsRedirectHandleCreate(&EBPF_HOOK_ALE_CONNECT_REDIRECT_PROVIDER, 0, &filter_context->redirect_handle);
        if (!NT_SUCCESS(status)) {
            result = EBPF_FAILED;
        }
        NET_EBPF_EXT_BAIL_ON_ERROR_RESULT(result);
    }

    // Add a single WFP filter at the WFP layer corresponding to the hook type, and set the hook NPI client as the
    // filter's raw context.
    result = net_ebpf_extension_add_wfp_filters(
        filter_parameters_array->count, // filter_count
        filter_parameters_array->filter_parameters,
        (compartment_id == UNSPECIFIED_COMPARTMENT_ID) ? 0 : 1,
        (compartment_id == UNSPECIFIED_COMPARTMENT_ID) ? NULL : &condition,
        (net_ebpf_extension_wfp_filter_context_t*)filter_context,
        &filter_context->base.filter_ids);
    NET_EBPF_EXT_BAIL_ON_ERROR_RESULT(result);

    // Set the filter context as the client context's provider data.
    net_ebpf_extension_hook_client_set_provider_data(
        (net_ebpf_extension_hook_client_t*)attaching_client, filter_context);

Exit:
    if (result != EBPF_SUCCESS) {
        if (filter_context != NULL) {
            if (filter_context->redirect_handle != NULL) {
                FwpsRedirectHandleDestroy(filter_context->redirect_handle);
            }
            ExFreePool(filter_context);
        }
    }

    NET_EBPF_EXT_RETURN_RESULT(result);
}

static void
_net_ebpf_extension_sock_addr_on_client_detach(_In_ const net_ebpf_extension_hook_client_t* detaching_client)
{
    NET_EBPF_EXT_LOG_ENTRY();
    net_ebpf_extension_sock_addr_wfp_filter_context_t* filter_context =
        (net_ebpf_extension_sock_addr_wfp_filter_context_t*)net_ebpf_extension_hook_client_get_provider_data(
            detaching_client);
    ASSERT(filter_context != NULL);
    net_ebpf_extension_delete_wfp_filters(filter_context->base.filter_ids_count, filter_context->base.filter_ids);
    if (filter_context->redirect_handle != NULL) {
        FwpsRedirectHandleDestroy(filter_context->redirect_handle);
    }
    net_ebpf_extension_wfp_filter_context_cleanup((net_ebpf_extension_wfp_filter_context_t*)filter_context);
}

static NTSTATUS
_net_ebpf_sock_addr_update_store_entries()
{
    NTSTATUS status;

    // Update section information.
    uint32_t section_info_count = sizeof(_ebpf_sock_addr_section_info) / sizeof(ebpf_program_section_info_t);
    status = _ebpf_store_update_section_information(&_ebpf_sock_addr_section_info[0], section_info_count);
    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_RETURN_NTSTATUS(status);
    }

    // Update program information.
    status = _ebpf_store_update_program_information(&_ebpf_sock_addr_program_info, 1);

    NET_EBPF_EXT_RETURN_NTSTATUS(status);
}

static NTSTATUS
_net_ebpf_sock_addr_create_security_descriptor()
{
    NTSTATUS status;
    ACL* dacl = NULL;
    uint32_t acl_length = 0;
    ACCESS_MASK access_mask = GENERIC_ALL;
    SECURITY_DESCRIPTOR* admin_security_descriptor = NULL;

    _net_ebpf_ext_generic_mapping = *(IoGetFileObjectGenericMapping());
    RtlMapGenericMask(&access_mask, &_net_ebpf_ext_generic_mapping);

    admin_security_descriptor = (SECURITY_DESCRIPTOR*)ExAllocatePoolUninitialized(
        NonPagedPoolNx, sizeof(SECURITY_DESCRIPTOR), NET_EBPF_EXTENSION_POOL_TAG);
    NET_EBPF_EXT_BAIL_ON_ALLOC_FAILURE_STATUS(
        NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR, admin_security_descriptor, "admin_sd", status);

    status = RtlCreateSecurityDescriptor(admin_security_descriptor, SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR, "RtlCreateSecurityDescriptor", status);

        goto Exit;
    }

    acl_length += sizeof(ACL);
    acl_length += RtlLengthSid(SeExports->SeAliasAdminsSid) + FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart);
    acl_length += RtlLengthSid(SeExports->SeLocalSystemSid) + FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart);

    dacl = (ACL*)ExAllocatePoolUninitialized(NonPagedPoolNx, acl_length, NET_EBPF_EXTENSION_POOL_TAG);
    NET_EBPF_EXT_BAIL_ON_ALLOC_FAILURE_STATUS(NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR, dacl, "dacl", status);

    RtlCreateAcl(dacl, acl_length, ACL_REVISION);

    status = RtlAddAccessAllowedAce(dacl, ACL_REVISION, access_mask, SeExports->SeAliasAdminsSid);
    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR, "RtlAddAccessAllowedAce", status);

        goto Exit;
    }
    status = RtlAddAccessAllowedAce(dacl, ACL_REVISION, access_mask, SeExports->SeLocalSystemSid);
    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR, "RtlAddAccessAllowedAce", status);
        goto Exit;
    }

    status = RtlSetDaclSecurityDescriptor(admin_security_descriptor, TRUE, dacl, FALSE);
    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR, "RtlSetDaclSecurityDescriptor", status);
        goto Exit;
    }

    _net_ebpf_ext_security_descriptor_admin = admin_security_descriptor;
    admin_security_descriptor = NULL;
    _net_ebpf_ext_dacl_admin = dacl;
    dacl = NULL;

Exit:
    if (dacl != NULL) {
        ExFreePool(dacl);
    }
    if (admin_security_descriptor != NULL) {
        ExFreePool(admin_security_descriptor);
    }

    NET_EBPF_EXT_RETURN_NTSTATUS(status);
}

static void
_net_ebpf_sock_addr_clean_up_security_descriptor()
{
    if (_net_ebpf_ext_dacl_admin != NULL) {
        ExFreePool(_net_ebpf_ext_dacl_admin);
        _net_ebpf_ext_dacl_admin = NULL;
    }
    if (_net_ebpf_ext_security_descriptor_admin != NULL) {
        ExFreePool(_net_ebpf_ext_security_descriptor_admin);
        _net_ebpf_ext_security_descriptor_admin = NULL;
    }
}

static void
_net_ebpf_sock_addr_initialize_globals()
{
    InitializeListHead(&_net_ebpf_ext_connect_context_list);
}

/**
 * @brief Compare the destination address in the two provided bpf_sock_addr_t structs.
 *
 * @param[in] addr1 Pointer to first sock_addr struct to compare.
 * @param[in] addr2 Pointer to second sock_addr struct to compare.

 * @return TRUE The addresses are same.
   @return FALSE The addresses are different.
 */
static inline BOOLEAN
_net_ebpf_ext_compare_destination_address(_In_ const bpf_sock_addr_t* addr1, _In_ const bpf_sock_addr_t* addr2)
{
    ASSERT(addr1->family == addr2->family);
    if (addr1->family != addr2->family) {
        return FALSE;
    }

    return INET_ADDR_EQUAL((ADDRESS_FAMILY)addr1->family, &addr1->user_ip4, &addr2->user_ip4);
}

#define CONNECTION_CONTEXT_INITIALIZATION_SET_TIMESTAMP 0x1

static void
_net_ebpf_extension_connection_context_initialize(
    _In_ const bpf_sock_addr_t* sock_addr_ctx,
    uint64_t transport_endpoint_handle,
    uint32_t flags,
    _Out_ net_ebpf_extension_connection_context_t* connection_context)
{
    bool set_timestamp = flags & CONNECTION_CONTEXT_INITIALIZATION_SET_TIMESTAMP;
    RtlCopyMemory(
        connection_context->address_info.destination_ip.ipv6,
        sock_addr_ctx->user_ip6,
        sizeof(connection_context->address_info.destination_ip));

    connection_context->address_info.destination_port = sock_addr_ctx->user_port;
    connection_context->address_info.family = sock_addr_ctx->family;
    connection_context->address_info.source_port = sock_addr_ctx->msg_src_port;
    connection_context->transport_endpoint_handle = transport_endpoint_handle;
    connection_context->protocol = (uint16_t)sock_addr_ctx->protocol;
    connection_context->compartment_id = sock_addr_ctx->compartment_id;
    if (set_timestamp) {
        connection_context->timestamp = CONVERT_100NS_UNITS_TO_MS(KeQueryInterruptTime());
    }
}

static net_ebpf_extension_connection_context_t*
_net_ebpf_ext_get_and_remove_connection_context(
    uint64_t transport_endpoint_handle, _In_ const bpf_sock_addr_t* sock_addr_ctx)
{
    KIRQL old_irql;
    net_ebpf_extension_connection_context_t local_connection_context = {0};
    net_ebpf_extension_connection_context_t* connection_context = NULL;

    _net_ebpf_extension_connection_context_initialize(
        sock_addr_ctx, transport_endpoint_handle, 0, &local_connection_context);
    old_irql = ExAcquireSpinLockExclusive(&_net_ebpf_ext_sock_addr_lock);

    LIST_ENTRY* list_entry = _net_ebpf_ext_connect_context_list.Flink;
    while (list_entry != &_net_ebpf_ext_connect_context_list) {
        net_ebpf_extension_connection_context_t* entry =
            CONTAINING_RECORD(list_entry, net_ebpf_extension_connection_context_t, list_entry);
        if (memcmp(
                &local_connection_context, entry, EBPF_OFFSET_OF(net_ebpf_extension_connection_context_t, timestamp)) ==
            0) {
            // Found matching entry. Remove it from the list and return.
            RemoveEntryList(&entry->list_entry);
            _net_ebpf_ext_connect_context_count--;
            connection_context = entry;
            break;
        }
        list_entry = list_entry->Flink;
    }

    ExReleaseSpinLockExclusive(&_net_ebpf_ext_sock_addr_lock, old_irql);

    NET_EBPF_EXT_RETURN_POINTER(net_ebpf_extension_connection_context_t*, connection_context);
}

_Requires_exclusive_lock_held_(_net_ebpf_ext_sock_addr_lock) static void _net_ebpf_ext_purge_lru_contexts_under_lock(
    BOOLEAN delete_all)
{
    uint64_t expiry_time = CONVERT_100NS_UNITS_TO_MS(KeQueryInterruptTime()) - EXPIRY_TIME;

    LIST_ENTRY* list_entry = _net_ebpf_ext_connect_context_list.Blink;
    while (list_entry != &_net_ebpf_ext_connect_context_list) {
        net_ebpf_extension_connection_context_t* entry =
            CONTAINING_RECORD(list_entry, net_ebpf_extension_connection_context_t, list_entry);
        if (!delete_all && entry->timestamp > expiry_time) {
            break;
        }
        list_entry = list_entry->Blink;
        RemoveEntryList(&entry->list_entry);

        _net_ebpf_ext_connect_context_count--;

        NET_EBPF_EXT_LOG_MESSAGE_UINT64(
            NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
            "_net_ebpf_ext_purge_lru_contexts_under_lock: Delete",
            entry->transport_endpoint_handle);

        ExFreePool(entry);
    }

    NET_EBPF_EXT_LOG_MESSAGE_UINT64(
        NET_EBPF_EXT_TRACELOG_LEVEL_INFO,
        NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
        "_net_ebpf_ext_purge_lru_contexts_under_lock",
        _net_ebpf_ext_connect_context_count);
}

static void
_net_ebpf_ext_purge_lru_contexts(BOOLEAN delete_all)
{
    KIRQL old_irql = ExAcquireSpinLockExclusive(&_net_ebpf_ext_sock_addr_lock);
    _net_ebpf_ext_purge_lru_contexts_under_lock(delete_all);
    ExReleaseSpinLockExclusive(&_net_ebpf_ext_sock_addr_lock, old_irql);
}

static void
_net_ebpf_ext_insert_connection_context_to_list(_Inout_ net_ebpf_extension_connection_context_t* connection_context)
{
    KIRQL old_irql = ExAcquireSpinLockExclusive(&_net_ebpf_ext_sock_addr_lock);

    // Insert the most recent entry at the head.
    InsertHeadList(&_net_ebpf_ext_connect_context_list, &connection_context->list_entry);
    _net_ebpf_ext_connect_context_count++;

    // Purge stale entries from the list.
    _net_ebpf_ext_purge_lru_contexts_under_lock(FALSE);

    ExReleaseSpinLockExclusive(&_net_ebpf_ext_sock_addr_lock, old_irql);
}

NTSTATUS
net_ebpf_ext_sock_addr_register_providers()
{
    NTSTATUS status = STATUS_SUCCESS;

    NET_EBPF_EXT_LOG_ENTRY();

    status = _net_ebpf_sock_addr_update_store_entries();
    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_RETURN_NTSTATUS(status);
    }

    status = _net_ebpf_sock_addr_create_security_descriptor();
    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_RETURN_NTSTATUS(status);
    }

    _net_ebpf_sock_addr_initialize_globals();

    const net_ebpf_extension_program_info_provider_parameters_t program_info_provider_parameters = {
        &_ebpf_sock_addr_program_info_provider_moduleid, &_ebpf_sock_addr_program_info_provider_data};

    // Set the program type as the provider module id.
    _ebpf_sock_addr_program_info_provider_moduleid.Guid = EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR;
    status = net_ebpf_extension_program_info_provider_register(
        &program_info_provider_parameters, &_ebpf_sock_addr_program_info_provider_context);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    for (int i = 0; i < NET_EBPF_SOCK_ADDR_HOOK_PROVIDER_COUNT; i++) {
        const net_ebpf_extension_hook_provider_parameters_t hook_provider_parameters = {
            &_ebpf_sock_addr_hook_provider_moduleid[i], &_net_ebpf_extension_sock_addr_hook_provider_data[i]};

        _net_ebpf_sock_addr_hook_provider_data[i].supported_program_type = EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR;
        _net_ebpf_sock_addr_hook_provider_data[i].bpf_attach_type =
            (bpf_attach_type_t)_net_ebpf_extension_sock_addr_bpf_attach_types[i];
        _net_ebpf_sock_addr_hook_provider_data[i].link_type = BPF_LINK_TYPE_CGROUP;
        _net_ebpf_extension_sock_addr_hook_provider_data[i].version = EBPF_ATTACH_PROVIDER_DATA_VERSION;
        _net_ebpf_extension_sock_addr_hook_provider_data[i].data = &_net_ebpf_sock_addr_hook_provider_data[i];
        _net_ebpf_extension_sock_addr_hook_provider_data[i].size = sizeof(ebpf_attach_provider_data_t);

        // Set the attach type as the provider module id.
        _ebpf_sock_addr_hook_provider_moduleid[i].Length = sizeof(NPI_MODULEID);
        _ebpf_sock_addr_hook_provider_moduleid[i].Type = MIT_GUID;
        _ebpf_sock_addr_hook_provider_moduleid[i].Guid = *_net_ebpf_extension_sock_addr_attach_types[i];
        // Register the provider context and pass the pointer to the WFP filter parameters
        // corresponding to this hook type as custom data.
        status = net_ebpf_extension_hook_provider_register(
            &hook_provider_parameters,
            _net_ebpf_extension_sock_addr_on_client_attach,
            _net_ebpf_extension_sock_addr_on_client_detach,
            &_net_ebpf_extension_sock_addr_wfp_filter_parameters[i],
            &_ebpf_sock_addr_hook_provider_context[i]);
        if (!NT_SUCCESS(status)) {
            goto Exit;
        }
    }

Exit:
    if (!NT_SUCCESS(status)) {
        net_ebpf_ext_sock_addr_unregister_providers();
        _net_ebpf_sock_addr_clean_up_security_descriptor();
    }
    NET_EBPF_EXT_RETURN_NTSTATUS(status);
}

void
net_ebpf_ext_sock_addr_unregister_providers()
{
    for (int i = 0; i < NET_EBPF_SOCK_ADDR_HOOK_PROVIDER_COUNT; i++) {
        if (_ebpf_sock_addr_hook_provider_context[i]) {
            net_ebpf_extension_hook_provider_unregister(_ebpf_sock_addr_hook_provider_context[i]);
            _ebpf_sock_addr_hook_provider_context[i] = NULL;
        }
    }
    if (_ebpf_sock_addr_program_info_provider_context) {
        net_ebpf_extension_program_info_provider_unregister(_ebpf_sock_addr_program_info_provider_context);
        _ebpf_sock_addr_program_info_provider_context = NULL;
    }

    _net_ebpf_ext_purge_lru_contexts(TRUE);
    _net_ebpf_sock_addr_clean_up_security_descriptor();
}

typedef enum _net_ebpf_extension_sock_addr_connection_direction
{
    EBPF_HOOK_SOCK_ADDR_INGRESS = 0,
    EBPF_HOOK_SOCK_ADDR_EGRESS
} net_ebpf_extension_sock_addr_connection_direction_t;

static net_ebpf_extension_sock_addr_connection_direction_t
_net_ebpf_extension_sock_addr_get_connection_direction_from_hook_id(net_ebpf_extension_hook_id_t hook_id)
{
    return ((hook_id == EBPF_HOOK_ALE_AUTH_CONNECT_V4) || (hook_id == EBPF_HOOK_ALE_AUTH_CONNECT_V6) ||
            (hook_id == EBPF_HOOK_ALE_CONNECT_REDIRECT_V4) || (hook_id == EBPF_HOOK_ALE_CONNECT_REDIRECT_V6))
               ? EBPF_HOOK_SOCK_ADDR_EGRESS
               : EBPF_HOOK_SOCK_ADDR_INGRESS;
}

const wfp_ale_layer_fields_t wfp_connection_fields[] = {
    // EBPF_HOOK_ALE_AUTH_CONNECT_V4
    {FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS,
     FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT,
     FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS,
     FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT,
     FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL,
     0, // No direction field in this layer.
     FWPS_FIELD_ALE_AUTH_CONNECT_V4_COMPARTMENT_ID,
     FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_INTERFACE,
     FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_USER_ID,
     FWPS_FIELD_ALE_AUTH_CONNECT_V4_FLAGS},

    // EBPF_HOOK_ALE_AUTH_CONNECT_V6
    {FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS,
     FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT,
     FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS,
     FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT,
     FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL,
     0, // No direction field in this layer.
     FWPS_FIELD_ALE_AUTH_CONNECT_V6_COMPARTMENT_ID,
     FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_INTERFACE,
     FWPS_FIELD_ALE_AUTH_CONNECT_V6_ALE_USER_ID,
     FWPS_FIELD_ALE_AUTH_CONNECT_V6_FLAGS},

    // EBPF_HOOK_ALE_CONNECT_REDIRECT_V4
    {FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_LOCAL_ADDRESS,
     FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_LOCAL_PORT,
     FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_ADDRESS,
     FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_PORT,
     FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_PROTOCOL,
     0, // No direction field in this layer.
     FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_COMPARTMENT_ID,
     0, // No interface luid in this layer.
     FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_ALE_USER_ID,
     FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_FLAGS},

    // EBPF_HOOK_ALE_CONNECT_REDIRECT_V6
    {FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_LOCAL_ADDRESS,
     FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_LOCAL_PORT,
     FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_REMOTE_ADDRESS,
     FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_REMOTE_PORT,
     FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_PROTOCOL,
     0, // No direction field in this layer.
     FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_COMPARTMENT_ID,
     0, // No interface luid in this layer.
     FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_ALE_USER_ID,
     FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_FLAGS},

    // EBPF_HOOK_ALE_AUTH_RECV_ACCEPT_V4
    {FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS,
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT,
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS,
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT,
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL,
     0, // No direction field in this layer.
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_COMPARTMENT_ID,
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_INTERFACE,
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_ALE_USER_ID,
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_FLAGS},

    // EBPF_HOOK_ALE_AUTH_RECV_ACCEPT_V6
    {FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_ADDRESS,
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_PORT,
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_ADDRESS,
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_PORT,
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_PROTOCOL,
     0, // No direction field in this layer.
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_COMPARTMENT_ID,
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_INTERFACE,
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_ALE_USER_ID,
     FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_FLAGS}};

static void
_net_ebpf_extension_sock_addr_copy_wfp_connection_fields(
    _In_ const FWPS_INCOMING_VALUES* incoming_fixed_values,
    _In_ const FWPS_INCOMING_METADATA_VALUES* incoming_metadata_values,
    _Out_ net_ebpf_sock_addr_t* sock_addr_ctx)
{
    net_ebpf_extension_hook_id_t hook_id =
        net_ebpf_extension_get_hook_id_from_wfp_layer_id(incoming_fixed_values->layerId);
    net_ebpf_extension_sock_addr_connection_direction_t direction =
        _net_ebpf_extension_sock_addr_get_connection_direction_from_hook_id(hook_id);
    const wfp_ale_layer_fields_t* fields = &wfp_connection_fields[hook_id - EBPF_HOOK_ALE_AUTH_CONNECT_V4];

    uint16_t source_ip_address_field =
        (direction == EBPF_HOOK_SOCK_ADDR_EGRESS) ? fields->local_ip_address_field : fields->remote_ip_address_field;
    uint16_t source_port_field =
        (direction == EBPF_HOOK_SOCK_ADDR_EGRESS) ? fields->local_port_field : fields->remote_port_field;
    uint16_t destination_ip_address_field =
        (direction == EBPF_HOOK_SOCK_ADDR_EGRESS) ? fields->remote_ip_address_field : fields->local_ip_address_field;
    uint16_t destination_port_field =
        (direction == EBPF_HOOK_SOCK_ADDR_EGRESS) ? fields->remote_port_field : fields->local_port_field;

    FWPS_INCOMING_VALUE0* incoming_values = incoming_fixed_values->incomingValue;

    // Copy IP address fields.
    if ((hook_id == EBPF_HOOK_ALE_AUTH_CONNECT_V4) || (hook_id == EBPF_HOOK_ALE_AUTH_RECV_ACCEPT_V4) ||
        (hook_id == EBPF_HOOK_ALE_CONNECT_REDIRECT_V4)) {
        sock_addr_ctx->base.family = AF_INET;
        sock_addr_ctx->base.msg_src_ip4 = htonl(incoming_values[source_ip_address_field].value.uint32);
        sock_addr_ctx->base.user_ip4 = htonl(incoming_values[destination_ip_address_field].value.uint32);
    } else {
        sock_addr_ctx->base.family = AF_INET6;
        RtlCopyMemory(
            sock_addr_ctx->base.msg_src_ip6,
            incoming_values[source_ip_address_field].value.byteArray16,
            sizeof(FWP_BYTE_ARRAY16));
        RtlCopyMemory(
            sock_addr_ctx->base.user_ip6,
            incoming_values[destination_ip_address_field].value.byteArray16,
            sizeof(FWP_BYTE_ARRAY16));
    }
    sock_addr_ctx->base.msg_src_port = htons(incoming_values[source_port_field].value.uint16);
    sock_addr_ctx->base.user_port = htons(incoming_values[destination_port_field].value.uint16);
    sock_addr_ctx->base.protocol = incoming_values[fields->protocol_field].value.uint8;
    sock_addr_ctx->base.compartment_id = incoming_values[fields->compartment_id_field].value.uint32;

    if (hook_id == EBPF_HOOK_ALE_CONNECT_REDIRECT_V4 || hook_id == EBPF_HOOK_ALE_CONNECT_REDIRECT_V6) {
        sock_addr_ctx->base.interface_luid = 0;
    } else {
        sock_addr_ctx->base.interface_luid = *incoming_values[fields->interface_luid_field].value.uint64;
    }

    // USER_ID is available for all sock_addr attach types.
    sock_addr_ctx->access_information =
        (TOKEN_ACCESS_INFORMATION*)(incoming_values[fields->user_id_field].value.byteBlob->data);

    if (incoming_metadata_values->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) {
        sock_addr_ctx->process_id = incoming_metadata_values->processId;
    } else {
        NET_EBPF_EXT_LOG_MESSAGE_UINT64(
            NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
            "FWPS_METADATA_FIELD_PROCESS_ID not present",
            hook_id);

        sock_addr_ctx->process_id = 0;
    }

    // Store the FLAGS field.
    sock_addr_ctx->flags = incoming_values[fields->flags_field].value.uint32;
}

//
// WFP callout callback functions.
//

void
net_ebpf_extension_sock_addr_authorize_recv_accept_classify(
    _In_ const FWPS_INCOMING_VALUES* incoming_fixed_values,
    _In_ const FWPS_INCOMING_METADATA_VALUES* incoming_metadata_values,
    _Inout_opt_ void* layer_data,
    _In_opt_ const void* classify_context,
    _In_ const FWPS_FILTER* filter,
    uint64_t flow_context,
    _Inout_ FWPS_CLASSIFY_OUT* classify_output)
{
    NET_EBPF_EXT_LOG_ENTRY();
    uint32_t result;
    net_ebpf_extension_sock_addr_wfp_filter_context_t* filter_context = NULL;
    net_ebpf_extension_hook_client_t* attached_client = NULL;
    net_ebpf_sock_addr_t net_ebpf_sock_addr_ctx = {0};
    bpf_sock_addr_t* sock_addr_ctx = &net_ebpf_sock_addr_ctx.base;
    uint32_t compartment_id = UNSPECIFIED_COMPARTMENT_ID;

    UNREFERENCED_PARAMETER(incoming_metadata_values);
    UNREFERENCED_PARAMETER(layer_data);
    UNREFERENCED_PARAMETER(classify_context);
    UNREFERENCED_PARAMETER(flow_context);

    classify_output->actionType = FWP_ACTION_PERMIT;

    filter_context = (net_ebpf_extension_sock_addr_wfp_filter_context_t*)filter->context;
    ASSERT(filter_context != NULL);
    if (filter_context == NULL) {
        goto Exit;
    }

    attached_client = (net_ebpf_extension_hook_client_t*)filter_context->base.client_context;
    if (attached_client == NULL) {
        goto Exit;
    }

    if (!net_ebpf_extension_hook_client_enter_rundown(attached_client)) {
        attached_client = NULL;
        goto Exit;
    }

    _net_ebpf_extension_sock_addr_copy_wfp_connection_fields(
        incoming_fixed_values, incoming_metadata_values, &net_ebpf_sock_addr_ctx);

    // eBPF programs will not be invoked on connection re-authorization.
    if (net_ebpf_sock_addr_ctx.flags & FWP_CONDITION_FLAG_IS_REAUTHORIZE) {
        goto Exit;
    }

    compartment_id = filter_context->compartment_id;
    ASSERT((compartment_id == UNSPECIFIED_COMPARTMENT_ID) || (compartment_id == sock_addr_ctx->compartment_id));
    if (compartment_id != UNSPECIFIED_COMPARTMENT_ID && compartment_id != sock_addr_ctx->compartment_id) {
        // The client is not interested in this compartment Id.
        NET_EBPF_EXT_LOG_MESSAGE_UINT32(
            NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
            "The cgroup_sock_addr eBPF program is not interested in this compartment ID",
            sock_addr_ctx->compartment_id);

        goto Exit;
    }

    if (net_ebpf_extension_hook_invoke_program(attached_client, sock_addr_ctx, &result) != EBPF_SUCCESS) {
        // Block the request if we failed to invoke the eBPF program.
        classify_output->actionType = FWP_ACTION_BLOCK;
        goto Exit;
    }

    classify_output->actionType = (result == BPF_SOCK_ADDR_VERDICT_PROCEED) ? FWP_ACTION_PERMIT : FWP_ACTION_BLOCK;
    if (classify_output->actionType == FWP_ACTION_BLOCK) {
        classify_output->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    }

    _net_ebpf_ext_log_sock_addr_classify(
        "recv_accept_classify", incoming_metadata_values->transportEndpointHandle, sock_addr_ctx, NULL, result);

Exit:
    if (attached_client) {
        net_ebpf_extension_hook_client_leave_rundown(attached_client);
    }

    NET_EBPF_EXT_LOG_EXIT();
}

/*
 * Default action is BLOCK. If this callout is being invoked, it means at least one
 * eBPF program is attached. Hence no connection should be allowed unless allowed by
 * the eBPF program.
 */
void
net_ebpf_extension_sock_addr_authorize_connection_classify(
    _In_ const FWPS_INCOMING_VALUES* incoming_fixed_values,
    _In_ const FWPS_INCOMING_METADATA_VALUES* incoming_metadata_values,
    _Inout_opt_ void* layer_data,
    _In_opt_ const void* classify_context,
    _In_ const FWPS_FILTER* filter,
    uint64_t flow_context,
    _Inout_ FWPS_CLASSIFY_OUT* classify_output)
{
    NET_EBPF_EXT_LOG_ENTRY();
    uint32_t verdict = BPF_SOCK_ADDR_VERDICT_REJECT;
    net_ebpf_extension_sock_addr_wfp_filter_context_t* filter_context = NULL;
    net_ebpf_sock_addr_t net_ebpf_sock_addr_ctx = {0};
    bpf_sock_addr_t* sock_addr_ctx = &net_ebpf_sock_addr_ctx.base;
    uint32_t compartment_id = UNSPECIFIED_COMPARTMENT_ID;
    net_ebpf_extension_connection_context_t* connection_context = NULL;

    UNREFERENCED_PARAMETER(incoming_metadata_values);
    UNREFERENCED_PARAMETER(layer_data);
    UNREFERENCED_PARAMETER(classify_context);
    UNREFERENCED_PARAMETER(flow_context);

    filter_context = (net_ebpf_extension_sock_addr_wfp_filter_context_t*)filter->context;
    ASSERT(filter_context != NULL);
    if (filter_context == NULL) {
        goto Exit;
    }

    _net_ebpf_extension_sock_addr_copy_wfp_connection_fields(
        incoming_fixed_values, incoming_metadata_values, &net_ebpf_sock_addr_ctx);

    if (net_ebpf_sock_addr_ctx.flags & FWP_CONDITION_FLAG_IS_REAUTHORIZE) {
        // This is a re-authorization of a connection that was previously authorized by the
        // eBPF program. Permit it.
        verdict = BPF_SOCK_ADDR_VERDICT_PROCEED;
        goto Exit;
    }

    compartment_id = filter_context->compartment_id;
    ASSERT((compartment_id == UNSPECIFIED_COMPARTMENT_ID) || (compartment_id == sock_addr_ctx->compartment_id));
    if (compartment_id != UNSPECIFIED_COMPARTMENT_ID && compartment_id != sock_addr_ctx->compartment_id) {
        // The client is not interested in this compartment Id.
        NET_EBPF_EXT_LOG_MESSAGE_UINT32(
            NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
            "The cgroup_sock_addr eBPF program is not interested in this compartment ID",
            sock_addr_ctx->compartment_id);

        verdict = BPF_SOCK_ADDR_VERDICT_PROCEED;
        goto Exit;
    }

    // Find and remove the connection context for this connection.
    connection_context = _net_ebpf_ext_get_and_remove_connection_context(
        incoming_metadata_values->transportEndpointHandle, sock_addr_ctx);
    if (connection_context == NULL) {
        // No blocked connection context was found for this AUTH request. So the connection is allowed.
        verdict = BPF_SOCK_ADDR_VERDICT_PROCEED;
        goto Exit;
    }
    verdict = BPF_SOCK_ADDR_VERDICT_REJECT;
    ExFreePool(connection_context);
    connection_context = NULL;

Exit:
    classify_output->actionType = (verdict == BPF_SOCK_ADDR_VERDICT_PROCEED) ? FWP_ACTION_PERMIT : FWP_ACTION_BLOCK;
    // Clear FWPS_RIGHT_ACTION_WRITE for block action.
    if (classify_output->actionType == FWP_ACTION_BLOCK) {
        classify_output->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    }

    _net_ebpf_ext_log_sock_addr_classify(
        "auth_classify", incoming_metadata_values->transportEndpointHandle, sock_addr_ctx, NULL, verdict);

    NET_EBPF_EXT_LOG_EXIT();
    return;
}

static BOOLEAN
_net_ebpf_ext_sock_addr_is_connection_locally_redirected_by_others(
    _In_ const FWPS_CONNECT_REQUEST* connect_request, uint64_t filter_id)
{
    FWPS_CONNECT_REQUEST* previous_connect_request = connect_request->previousVersion;
    while (previous_connect_request != NULL) {
        if ((previous_connect_request->modifierFilterId != filter_id) &&
            (previous_connect_request->localRedirectHandle != NULL)) {
            NET_EBPF_EXT_LOG_MESSAGE_UINT64(
                NET_EBPF_EXT_TRACELOG_LEVEL_INFO,
                NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
                "Connection previously locally redirected",
                previous_connect_request->modifierFilterId);

            return TRUE;
        }
        previous_connect_request = previous_connect_request->previousVersion;
    }
    return FALSE;
}

static _Must_inspect_result_ NTSTATUS
_net_ebpf_ext_process_redirect_verdict(
    _In_ const bpf_sock_addr_t* original_context,
    _In_ const bpf_sock_addr_t* redirected_context,
    _In_ const FWPS_FILTER* filter,
    uint64_t classify_handle,
    HANDLE redirect_handle,
    _Out_ bool* redirected,
    _Inout_ FWPS_CLASSIFY_OUT* classify_output)
{
    NTSTATUS status = STATUS_SUCCESS;
    FWPS_CONNECT_REQUEST* connect_request = NULL;
    BOOLEAN commit_layer_data = FALSE;

    *redirected = FALSE;

    // Check if destination IP and/or port have been modified.
    BOOLEAN address_changed = !_net_ebpf_ext_compare_destination_address(redirected_context, original_context);
    if (redirected_context->user_port != original_context->user_port || address_changed) {
        *redirected = TRUE;

        status = FwpsAcquireWritableLayerDataPointer(
            classify_handle, filter->filterId, 0, (PVOID*)&connect_request, classify_output);
        if (!NT_SUCCESS(status)) {
            NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_UINT64_UINT64(
                NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
                "FwpsAcquireWritableLayerDataPointer",
                status,
                filter->filterId,
                (uint64_t)redirected_context->compartment_id);

            goto Exit;
        }
        commit_layer_data = TRUE;

        if (_net_ebpf_ext_sock_addr_is_connection_locally_redirected_by_others(connect_request, filter->filterId)) {
            // Since this connection has been redirected to a local proxy, it should not be redirected once more.
            // Once the local proxy sends out another outbound connection to the original destination,
            // that connection will get intercepted again and the eBPF program will be invoked again.
            goto Exit;
        }

        if (redirected_context->user_port != original_context->user_port) {
            INETADDR_SET_PORT((PSOCKADDR)&connect_request->remoteAddressAndPort, redirected_context->user_port);
        }
        if (address_changed) {
            uint8_t* address;
            if (redirected_context->family == AF_INET) {
                address = (uint8_t*)&redirected_context->user_ip4;
            } else {
                address = (uint8_t*)&(redirected_context->user_ip6[0]);
            }
            INETADDR_SET_ADDRESS((PSOCKADDR)&connect_request->remoteAddressAndPort, address);
        }

        connect_request->localRedirectTargetPID = TARGET_PROCESS_ID;
        connect_request->localRedirectHandle = redirect_handle;
    }

Exit:
    if (commit_layer_data) {
        FwpsApplyModifiedLayerData(classify_handle, connect_request, 0);
    }

    NET_EBPF_EXT_RETURN_NTSTATUS(status);
}

/**
 * @brief This function determines if the sock_addr eBPF program should be invoked as part of processing the classify
 * callback at CONNECT_REDIRECT layer.
 *
 * @param[in] filter_context Pointer to net_ebpf_extension_sock_addr_wfp_filter_context_t associated with WFP filter.
 * @param[in] sock_addr_ctx Pointer to bpf_sock_addr_t struct to be passed to eBPF program.
 * @param[in] v4_mapped Boolean indicating if the IP address in sock_addr is v4 mapped v6 address or not.
 *
 * @returns True if eBPF program should be invoked, False otherwise.
 */

_Must_inspect_result_ bool
_net_ebpf_extension_sock_addr_should_invoke_ebpf_program(
    _In_ const net_ebpf_extension_sock_addr_wfp_filter_context_t* filter_context,
    _In_ const bpf_sock_addr_t* sock_addr_ctx,
    bool v4_mapped)
{
    bool process_classify = TRUE;

    //  If the callout is invoked for v4, then it is safe to invoke the eBPF program.
    if (sock_addr_ctx->family == AF_INET) {
        goto Exit;
    }

    //  If the callout is invoked for v6:
    //  1. Check if the destination is v4-mapped v6 address or pure v6 address.
    //  2. If it is v4-mapped v6 address, then we should proceed only if this callout
    //     is invoked for v4 attach type.
    //  3. If it is pure v6 address, then we should proceed only if this callout is
    //     invoked for v6 attach type.

    if (v4_mapped) {
        if (!filter_context->v4_attach_type) {
            // This filter is for v6 attach type, but address is v4-mapped v6 address.
            NET_EBPF_EXT_LOG_MESSAGE(
                NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
                NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
                "net_ebpf_extension_sock_addr_redirect_connection_classify: v6 attach type, v4mapped address, "
                "ignoring");
            process_classify = FALSE;
            goto Exit;
        }
    } else if (filter_context->v4_attach_type) {
        // This filter is for v4 attach type, but address is a pure v6 address.
        NET_EBPF_EXT_LOG_MESSAGE(
            NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
            "net_ebpf_extension_sock_addr_redirect_connection_classify: v4 attach type, IPv6 address, ignoring");
        process_classify = FALSE;
        goto Exit;
    }

Exit:
    NET_EBPF_EXT_RETURN_BOOL(process_classify);
}

/*
 * For every eBPF sock_addr program attached to INET_CONNECT attach point (for a given compartment), a WFP filter
 * is added to the WFP CONNECT_REDIRECT (with the compartment Id as filter condition). So, this classify callback
 * function will be invoked for every new connection in the compartment. And so, the eBPF program attached
 * to the compartment will get invoked for every new connection.
 * If the program returns a PROCEED verdict, the connection is permitted by the callout.
 * If the program modifies the destination IP of the connection, connection redirection will be performed by this
 * callout. If the If on the other hand, the program returns a REJECT verdict, that decision will be cached and enforced
 * later by a corresponding callout at WFP AUTH_CONNECT layer.
 * By default, the local variable for verdict is set to REJECT.
 */
void
net_ebpf_extension_sock_addr_redirect_connection_classify(
    _In_ const FWPS_INCOMING_VALUES* incoming_fixed_values,
    _In_ const FWPS_INCOMING_METADATA_VALUES* incoming_metadata_values,
    _Inout_opt_ void* layer_data,
    _In_opt_ const void* classify_context,
    _In_ const FWPS_FILTER* filter,
    uint64_t flow_context,
    _Inout_ FWPS_CLASSIFY_OUT* classify_output)
{
    NET_EBPF_EXT_LOG_ENTRY();
    uint32_t verdict = BPF_SOCK_ADDR_VERDICT_REJECT;
    NTSTATUS status = STATUS_SUCCESS;
    ebpf_result_t result = EBPF_SUCCESS;
    net_ebpf_extension_sock_addr_wfp_filter_context_t* filter_context = NULL;
    net_ebpf_extension_hook_client_t* attached_client = NULL;
    net_ebpf_sock_addr_t net_ebpf_sock_addr_ctx = {0};
    bpf_sock_addr_t* sock_addr_ctx = (bpf_sock_addr_t*)&net_ebpf_sock_addr_ctx.base;
    bpf_sock_addr_t sock_addr_ctx_original = {0};
    uint32_t compartment_id = UNSPECIFIED_COMPARTMENT_ID;
    bool v4_mapped = FALSE;
    FWPS_CONNECTION_REDIRECT_STATE redirect_state;
    HANDLE redirect_handle;
    uint64_t classify_handle = 0;
    bool classify_handle_acquired = FALSE;
    bool redirected = FALSE;
    net_ebpf_extension_connection_context_t* blocked_connection_context = NULL;

    UNREFERENCED_PARAMETER(layer_data);
    UNREFERENCED_PARAMETER(flow_context);

    if ((classify_output->rights & FWPS_RIGHT_ACTION_WRITE) == 0) {
        // A callout with higher weight has revoked the write permission. Bail out.
        NET_EBPF_EXT_LOG_MESSAGE(
            NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
            "No \"write\" right; exiting.");
        verdict = BPF_SOCK_ADDR_VERDICT_PROCEED;
        NET_EBPF_EXT_LOG_EXIT();
        return;
    }

    filter_context = (net_ebpf_extension_sock_addr_wfp_filter_context_t*)filter->context;
    ASSERT(filter_context != NULL);
    if (filter_context == NULL) {
        NET_EBPF_EXT_LOG_MESSAGE_NTSTATUS(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
            "filter_context is NULL.",
            STATUS_INVALID_PARAMETER);
        goto Exit;
    }

    // Populate the sock_addr context with WFP classify input fields.
    _net_ebpf_extension_sock_addr_copy_wfp_connection_fields(
        incoming_fixed_values, incoming_metadata_values, &net_ebpf_sock_addr_ctx);
    memcpy(&sock_addr_ctx_original, sock_addr_ctx, sizeof(sock_addr_ctx_original));

    compartment_id = filter_context->compartment_id;
    ASSERT((compartment_id == UNSPECIFIED_COMPARTMENT_ID) || (compartment_id == sock_addr_ctx->compartment_id));
    if (compartment_id != UNSPECIFIED_COMPARTMENT_ID && compartment_id != sock_addr_ctx->compartment_id) {
        // The client is not interested in this compartment Id.
        NET_EBPF_EXT_LOG_MESSAGE_UINT32(
            NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
            "The cgroup_sock_addr eBPF program is not interested in this compartment ID.",
            sock_addr_ctx->compartment_id);
        verdict = BPF_SOCK_ADDR_VERDICT_PROCEED;
        goto Exit;
    }

    attached_client = (net_ebpf_extension_hook_client_t*)filter_context->base.client_context;
    if (attached_client == NULL) {
        NET_EBPF_EXT_LOG_MESSAGE_NTSTATUS(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
            "attached_client is NULL.",
            STATUS_INVALID_PARAMETER);
        goto Exit;
    }
    if (!net_ebpf_extension_hook_client_enter_rundown(attached_client)) {
        attached_client = NULL;
        // Client is detaching.
        NET_EBPF_EXT_LOG_MESSAGE(
            NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE, NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR, "Client is detaching.");
        verdict = BPF_SOCK_ADDR_VERDICT_PROCEED;
        goto Exit;
    }

    // Get the redirect handle for this filter.
    redirect_handle = filter_context->redirect_handle;
    ASSERT(redirect_handle != NULL);

    // Fetch redirect state.
    redirect_state = FwpsQueryConnectionRedirectState(incoming_metadata_values->redirectRecords, redirect_handle, NULL);
    if (redirect_state == FWPS_CONNECTION_REDIRECTED_BY_SELF ||
        redirect_state == FWPS_CONNECTION_PREVIOUSLY_REDIRECTED_BY_SELF) {
        NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
            "Connection redirected by self, ignoring.",
            filter->filterId,
            (uint64_t)sock_addr_ctx->compartment_id);

        // This connection was previously redirected.
        verdict = BPF_SOCK_ADDR_VERDICT_PROCEED;
        goto Exit;
    }

    v4_mapped = (sock_addr_ctx->family == AF_INET6) && IN6_IS_ADDR_V4MAPPED((IN6_ADDR*)sock_addr_ctx->user_ip6);

    // Check if the eBPF program should be invoked based on the IP address family and the hook attach type.
    if (!_net_ebpf_extension_sock_addr_should_invoke_ebpf_program(filter_context, sock_addr_ctx, v4_mapped)) {
        verdict = BPF_SOCK_ADDR_VERDICT_PROCEED;
        goto Exit;
    }

#pragma warning(push)
// SAL annotation for FwpsAcquireClassifyHandle for classify_context is _In_ whereas,
// the SAL for the same parameter in classifyFn callback _In_opt_ which causes a SAL error.
#pragma warning(suppress : 6387)
    // Acquire classify handle.
    status = FwpsAcquireClassifyHandle((void*)classify_context, 0, &classify_handle);
#pragma warning(pop)
    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_UINT64_UINT64(
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
            "FwpsAcquireClassifyHandle",
            status,
            filter->filterId,
            (uint64_t)sock_addr_ctx->compartment_id);

        goto Exit;
    }
    classify_handle_acquired = TRUE;

    if (v4_mapped) {
        // Change sock_addr_ctx to using IPv4 address for the eBPF program.
        sock_addr_ctx->family = AF_INET;
        const uint8_t* v4_ip = IN6_GET_ADDR_V4MAPPED((IN6_ADDR*)&sock_addr_ctx->user_ip6);
        uint32_t local_v4_ip = *((uint32_t*)v4_ip);
        memset(sock_addr_ctx->user_ip6, 0, 16);
        sock_addr_ctx->user_ip4 = local_v4_ip;
    }

    result = net_ebpf_extension_hook_invoke_program(attached_client, sock_addr_ctx, &verdict);
    NET_EBPF_EXT_BAIL_ON_ERROR_RESULT(result);

    if (verdict == BPF_SOCK_ADDR_VERDICT_REJECT) {
        NET_EBPF_EXT_LOG_MESSAGE(
            NET_EBPF_EXT_TRACELOG_LEVEL_WARNING,
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
            "cgroup_sock_addr eBPF program returned REJECT verdict.");
        goto Exit;
    }

    if (verdict == BPF_SOCK_ADDR_VERDICT_PROCEED) {
        if (v4_mapped) {
            // Revert back the sock_addr_ctx to v4-mapped v6 address for conenction-redirection processing.
            sock_addr_ctx->family = AF_INET6;
            IN_ADDR v4_address = *((IN_ADDR*)&sock_addr_ctx->user_ip4);
            IN6_SET_ADDR_V4MAPPED((IN6_ADDR*)&sock_addr_ctx->user_ip6, (IN_ADDR*)&v4_address);
        }
        status = _net_ebpf_ext_process_redirect_verdict(
            &sock_addr_ctx_original,
            sock_addr_ctx,
            filter,
            classify_handle,
            redirect_handle,
            &redirected,
            classify_output);
        NET_EBPF_EXT_BAIL_ON_ERROR_STATUS(status);

        (redirected) ? InterlockedIncrement(&_net_ebpf_ext_statistics.redirect_connection_count)
                     : InterlockedIncrement(&_net_ebpf_ext_statistics.permit_connection_count);
    }

    _net_ebpf_ext_log_sock_addr_classify(
        "connect_redirect_classify",
        incoming_metadata_values->transportEndpointHandle,
        &sock_addr_ctx_original,
        redirected ? sock_addr_ctx : NULL,
        verdict);

Exit:
    if (verdict == BPF_SOCK_ADDR_VERDICT_REJECT) {
        // Create a blocked connection context and add it to list for the AUTH_CONNECT layer callout to enforce the
        // verdict of the program.
        // Since the eBPF program turned in a REJECT verdict, there is no need to process
        // connection redirection, even if the program modified the destination.

        blocked_connection_context = (net_ebpf_extension_connection_context_t*)ExAllocatePoolUninitialized(
            NonPagedPoolNx, sizeof(net_ebpf_extension_connection_context_t), NET_EBPF_EXTENSION_POOL_TAG);
        NET_EBPF_EXT_BAIL_ON_ALLOC_FAILURE_STATUS(
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR, blocked_connection_context, "blocked_connection", status);
        memset(blocked_connection_context, 0, sizeof(net_ebpf_extension_connection_context_t));

        _net_ebpf_extension_connection_context_initialize(
            sock_addr_ctx,
            incoming_metadata_values->transportEndpointHandle,
            CONNECTION_CONTEXT_INITIALIZATION_SET_TIMESTAMP,
            blocked_connection_context);

        _net_ebpf_ext_insert_connection_context_to_list(blocked_connection_context);

        InterlockedIncrement(&_net_ebpf_ext_statistics.block_connection_count);
    }
    // Callout at CONNECT_REDIRECT layer always returns WFP action PERMIT.
    // If the eBPF program was invoked and it returned a REJECT verdict, it would be enforced by the callout at
    // AUTH_CONNECT layer further downstream.

    classify_output->actionType = FWP_ACTION_PERMIT;

    if (classify_handle_acquired) {
        FwpsReleaseClassifyHandle(classify_handle);
    }

    if (attached_client) {
        net_ebpf_extension_hook_client_leave_rundown(attached_client);
    }

    NET_EBPF_EXT_LOG_EXIT();
}

static ebpf_result_t
_ebpf_sock_addr_context_create(
    _In_reads_bytes_opt_(data_size_in) const uint8_t* data_in,
    size_t data_size_in,
    _In_reads_bytes_opt_(context_size_in) const uint8_t* context_in,
    size_t context_size_in,
    _Outptr_ void** context)
{
    NET_EBPF_EXT_LOG_ENTRY();

    ebpf_result_t result;
    bpf_sock_addr_t* sock_addr_ctx = NULL;

    *context = NULL;

    // This does not use the data_in parameters.
    if (data_size_in != 0 || data_in != NULL) {
        NET_EBPF_EXT_LOG_MESSAGE(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR, NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR, "Data is not supported");
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    // This requires context_in parameters.
    if (context_size_in < sizeof(bpf_sock_addr_t) || context_in == NULL) {
        NET_EBPF_EXT_LOG_MESSAGE(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR, NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR, "Context is required");
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    sock_addr_ctx = (bpf_sock_addr_t*)ExAllocatePoolUninitialized(
        NonPagedPoolNx, sizeof(bpf_sock_addr_t), NET_EBPF_EXTENSION_POOL_TAG);
    NET_EBPF_EXT_BAIL_ON_ALLOC_FAILURE_RESULT(
        NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR, sock_addr_ctx, "sock_addr_ctx", result);

    memcpy(sock_addr_ctx, context_in, sizeof(bpf_sock_addr_t));

    result = EBPF_SUCCESS;
    *context = sock_addr_ctx;

    sock_addr_ctx = NULL;

Exit:
    if (sock_addr_ctx) {
        ExFreePool(sock_addr_ctx);
    }
    NET_EBPF_EXT_RETURN_RESULT(result);
}

static void
_ebpf_sock_addr_context_destroy(
    _In_opt_ void* context,
    _Out_writes_bytes_to_(*data_size_out, *data_size_out) uint8_t* data_out,
    _Inout_ size_t* data_size_out,
    _Out_writes_bytes_to_(*context_size_out, *context_size_out) uint8_t* context_out,
    _Inout_ size_t* context_size_out)
{
    NET_EBPF_EXT_LOG_ENTRY();

    UNREFERENCED_PARAMETER(data_out);
    *data_size_out = 0;

    if (!context) {
        return;
    }

    if (context_out != NULL && *context_size_out >= sizeof(bpf_sock_addr_t)) {
        memcpy(context_out, context, sizeof(bpf_sock_addr_t));
        *context_size_out = sizeof(bpf_sock_addr_t);
    } else {
        *context_size_out = 0;
    }

    if (context) {
        ExFreePool(context);
    }
    NET_EBPF_EXT_LOG_EXIT();
}
