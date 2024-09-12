// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

/**
 * @file
 * @brief This file implements the hook for the CGROUP_SOCK_ADDR program type and associated attach types, on eBPF for
 * Windows.
 */

#include "ebpf_shared_framework.h"
#include "net_ebpf_ext_sock_addr.h"

#define TARGET_PROCESS_ID 1234
#define EXPIRY_TIME 60000 // 60 seconds in ms.
#define CONVERT_100NS_UNITS_TO_MS(x) ((x) / 10000)
#define LOW_MEMORY_CONNECTION_CONTEXT_COUNT 1000

#define CLEAN_UP_SOCK_ADDR_FILTER_CONTEXT(filter_context)                 \
    if ((filter_context) != NULL) {                                       \
        if ((filter_context)->redirect_handle != NULL) {                  \
            FwpsRedirectHandleDestroy((filter_context)->redirect_handle); \
        }                                                                 \
        CLEAN_UP_FILTER_CONTEXT(&(filter_context)->base);                 \
    }

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

#define DEFINE_SOCK_ADDR_CLASSIFY_LOG_FUNCTION(family)                                 \
    __declspec(noinline) static void _net_ebpf_ext_log_sock_addr_classify_v##family##( \
        _In_z_ const char* message,                                                    \
        uint64_t transport_endpoint_handle,                                            \
        _In_ const bpf_sock_addr_t* original_context,                                  \
        _In_opt_ const bpf_sock_addr_t* redirected_context,                            \
        uint32_t verdict)                                                              \
    {                                                                                  \
        if (redirected_context != NULL) {                                              \
            NET_EBPF_EXT_LOG_SOCK_ADDR_REDIRECT_CLASSIFY_IPV##family##(                \
                message,                                                               \
                transport_endpoint_handle,                                             \
                original_context->protocol,                                            \
                original_context->msg_src_ip##family##,                                \
                ntohs(original_context->msg_src_port),                                 \
                original_context->user_ip##family##,                                   \
                ntohs(original_context->user_port),                                    \
                redirected_context->user_ip##family##,                                 \
                ntohs(redirected_context->user_port),                                  \
                verdict);                                                              \
        } else {                                                                       \
            if (verdict == BPF_SOCK_ADDR_VERDICT_REJECT) {                             \
                NET_EBPF_EXT_LOG_SOCK_ADDR_CLASSIFY_IPV##family##(                     \
                    NET_EBPF_EXT_TRACELOG_LEVEL_INFO,                                  \
                    message,                                                           \
                    transport_endpoint_handle,                                         \
                    original_context->protocol,                                        \
                    original_context->msg_src_ip##family##,                            \
                    ntohs(original_context->msg_src_port),                             \
                    original_context->user_ip##family##,                               \
                    ntohs(original_context->user_port),                                \
                    verdict);                                                          \
            } else {                                                                   \
                NET_EBPF_EXT_LOG_SOCK_ADDR_CLASSIFY_IPV##family##(                     \
                    NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,                               \
                    message,                                                           \
                    transport_endpoint_handle,                                         \
                    original_context->protocol,                                        \
                    original_context->msg_src_ip##family##,                            \
                    ntohs(original_context->msg_src_port),                             \
                    original_context->user_ip##family##,                               \
                    ntohs(original_context->user_port),                                \
                    verdict);                                                          \
            }                                                                          \
        }                                                                              \
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
    EBPF_CONTEXT_HEADER;
    bpf_sock_addr_t base;
    TOKEN_ACCESS_INFORMATION* access_information;
    uint64_t process_id;
    uint32_t flags;
    net_ebpf_extension_hook_id_t hook_id;
    void* redirect_context;
    uint32_t redirect_context_size;
    uint64_t transport_endpoint_handle;
    bpf_sock_addr_t* original_context;
    bool redirected : 1;
    bool address_changed : 1;
    bool v4_mapped : 1;
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
    // Counter for the number of times a pre-allocated low memory context was used.
    volatile long low_memory_context_count;
} net_ebpf_ext_sock_addr_statistics_t;

static net_ebpf_ext_sock_addr_statistics_t _net_ebpf_ext_statistics;

typedef struct _net_ebpf_ext_sock_addr_connection_contexts
{
    EX_SPIN_LOCK lock;
    // This list is used to ensure that contexts are never leaked and are freed after some time.
    _Guarded_by_(lock) LIST_ENTRY blocked_context_lru_list;
    // This list stores blocked connection contexts at the connect_redirect, to be retrieved and removed at the connect
    // layer.
    _Guarded_by_(lock) RTL_AVL_TABLE blocked_context_table;
    uint32_t blocked_context_count;

    // This list stores pre-allocated contexts, to be used under low memory conditions.
    _Guarded_by_(lock) LIST_ENTRY low_memory_free_context_list;
    // This list is used in place of the table under low memory conditions, when we fail to allocate entries.
    _Guarded_by_(lock) LIST_ENTRY low_memory_blocked_context_list;
    uint32_t low_memory_blocked_context_count;
} net_ebpf_ext_sock_addr_connection_contexts_t;

static net_ebpf_ext_sock_addr_connection_contexts_t _net_ebpf_ext_sock_addr_blocked_contexts = {0};

static SECURITY_DESCRIPTOR* _net_ebpf_ext_security_descriptor_admin = NULL;
static ACL* _net_ebpf_ext_dacl_admin = NULL;
static GENERIC_MAPPING _net_ebpf_ext_generic_mapping = {0};

static bool
_net_ebpf_extension_sock_addr_process_verdict(_Inout_ void* program_context, int program_verdict);

//
// sock_addr helper functions.
//
static uint32_t
_get_thread_id()
{
    return (uint32_t)(uintptr_t)PsGetCurrentThreadId();
}

static uint64_t
_ebpf_sock_addr_get_current_pid_tgid_implicit(
    uint64_t dummy_param1,
    uint64_t dummy_param2,
    uint64_t dummy_param3,
    uint64_t dummy_param4,
    uint64_t dummy_param5,
    _In_ const bpf_sock_addr_t* ctx)
{
    UNREFERENCED_PARAMETER(dummy_param1);
    UNREFERENCED_PARAMETER(dummy_param2);
    UNREFERENCED_PARAMETER(dummy_param3);
    UNREFERENCED_PARAMETER(dummy_param4);
    UNREFERENCED_PARAMETER(dummy_param5);

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

static uint64_t
_ebpf_sock_addr_get_socket_cookie(_In_ const bpf_sock_addr_t* ctx)
{
    net_ebpf_sock_addr_t* sock_addr_ctx = CONTAINING_RECORD(ctx, net_ebpf_sock_addr_t, base);
    return sock_addr_ctx->transport_endpoint_handle;
}

static uint64_t
_ebpf_sock_addr_get_current_pid_tgid(_In_ const bpf_sock_addr_t* ctx)
{
    net_ebpf_sock_addr_t* sock_addr_ctx = CONTAINING_RECORD(ctx, net_ebpf_sock_addr_t, base);
    return (sock_addr_ctx->process_id << 32 | _get_thread_id());
}

static int
_ebpf_sock_addr_set_redirect_context(_In_ const bpf_sock_addr_t* ctx, _In_ void* data, _In_ uint32_t data_size)
{
    int return_value = 0;
    net_ebpf_sock_addr_t* sock_addr_ctx = CONTAINING_RECORD(ctx, net_ebpf_sock_addr_t, base);
    void* redirect_context = NULL;

    // Check for invalid parameters.
    if (data == NULL || data_size == 0) {
        return_value = -1;
        goto Exit;
    }

    // This function is only supported at the connect redirect layer.
    if (sock_addr_ctx->hook_id != EBPF_HOOK_ALE_CONNECT_REDIRECT_V4 &&
        sock_addr_ctx->hook_id != EBPF_HOOK_ALE_CONNECT_REDIRECT_V6) {
        NET_EBPF_EXT_LOG_MESSAGE(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
            "_ebpf_sock_addr_set_redirect_context invoked at incorrect hook.");
        return_value = -1;
        goto Exit;
    }

    // Allocate buffer to store redirect context.
    redirect_context = ExAllocatePoolUninitialized(NonPagedPoolNx, data_size, NET_EBPF_EXTENSION_POOL_TAG);
    if (redirect_context == NULL) {
        NET_EBPF_EXT_LOG_MESSAGE(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
            "_ebpf_sock_addr_set_redirect_context failed to allocate memory for the redirect context.");
        return_value = -1;
        goto Exit;
    }
    memcpy(redirect_context, data, data_size);

    // If a redirect context already exists, free the existing buffer.
    if (sock_addr_ctx->redirect_context != NULL) {
        ExFreePool(sock_addr_ctx->redirect_context);
    }

    // Set the redirect context.
    sock_addr_ctx->redirect_context = redirect_context;
    sock_addr_ctx->redirect_context_size = data_size;

Exit:
    if (return_value == -1) {
        NET_EBPF_EXT_LOG_FUNCTION_ERROR(return_value);
    }

    return return_value;
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
     L"net eBPF sock_addr hook WFP filter",
     FWP_ACTION_CALLOUT_UNKNOWN},

    {&FWPM_LAYER_ALE_CONNECT_REDIRECT_V6,
     &EBPF_HOOK_CGROUP_CONNECT_V4_SUBLAYER,
     &EBPF_HOOK_ALE_CONNECT_REDIRECT_V6_CALLOUT,
     L"net eBPF sock_addr hook",
     L"net eBPF sock_addr hook WFP filter",
     FWP_ACTION_CALLOUT_UNKNOWN}};

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
     L"net eBPF sock_addr hook WFP filter",
     FWP_ACTION_CALLOUT_UNKNOWN}};

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

_Requires_exclusive_lock_held_(_net_ebpf_ext_sock_addr_blocked_contexts
                                   .lock) static void _net_ebpf_ext_purge_blocked_connect_contexts(bool delete_all);

//
// SOCK_ADDR Program Information NPI Provider.
//

static const void* _ebpf_sock_addr_specific_helper_functions[] = {
    (void*)_ebpf_sock_addr_get_current_pid_tgid, (void*)_ebpf_sock_addr_set_redirect_context};

static ebpf_helper_function_addresses_t _ebpf_sock_addr_specific_helper_function_address_table = {
    EBPF_HELPER_FUNCTION_ADDRESSES_HEADER,
    EBPF_COUNT_OF(_ebpf_sock_addr_specific_helper_functions),
    (uint64_t*)_ebpf_sock_addr_specific_helper_functions};

static const void* _ebpf_sock_addr_global_helper_functions[] = {
    (void*)_ebpf_sock_addr_get_current_pid_tgid_implicit,
    (void*)_ebpf_sock_addr_get_current_logon_id,
    (void*)_ebpf_sock_addr_is_current_admin,
    (void*)_ebpf_sock_addr_get_socket_cookie};

static ebpf_helper_function_addresses_t _ebpf_sock_addr_global_helper_function_address_table = {
    EBPF_HELPER_FUNCTION_ADDRESSES_HEADER,
    EBPF_COUNT_OF(_ebpf_sock_addr_global_helper_functions),
    (uint64_t*)_ebpf_sock_addr_global_helper_functions};

static ebpf_program_data_t _ebpf_sock_addr_program_data = {
    .header = EBPF_PROGRAM_DATA_HEADER,
    .program_info = &_ebpf_sock_addr_program_info,
    .program_type_specific_helper_function_addresses = &_ebpf_sock_addr_specific_helper_function_address_table,
    .global_helper_function_addresses = &_ebpf_sock_addr_global_helper_function_address_table,
    .context_create = &_ebpf_sock_addr_context_create,
    .context_destroy = &_ebpf_sock_addr_context_destroy,
    .required_irql = DISPATCH_LEVEL,
    .capabilities = {.supports_context_header = true},
};

// Set the program type as the provider module id.
NPI_MODULEID DECLSPEC_SELECTANY _ebpf_sock_addr_program_info_provider_moduleid = {
    sizeof(NPI_MODULEID), MIT_GUID, EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR_GUID};

static net_ebpf_extension_program_info_provider_t* _ebpf_sock_addr_program_info_provider_context = NULL;

//
// SOCK_ADDR Hook NPI Provider.
//

ebpf_attach_provider_data_t _net_ebpf_sock_addr_hook_provider_data[NET_EBPF_SOCK_ADDR_HOOK_PROVIDER_COUNT] = {0};
NPI_MODULEID DECLSPEC_SELECTANY _ebpf_sock_addr_hook_provider_moduleid[NET_EBPF_SOCK_ADDR_HOOK_PROVIDER_COUNT] = {0};

static net_ebpf_extension_hook_provider_t*
    _ebpf_sock_addr_hook_provider_context[NET_EBPF_SOCK_ADDR_HOOK_PROVIDER_COUNT] = {0};

static ebpf_result_t
_net_ebpf_extension_sock_addr_validate_client_data(
    _In_ const ebpf_extension_data_t* client_data, _Out_ bool* is_wildcard)
{
    ebpf_result_t result = EBPF_SUCCESS;
    uint32_t compartment_id;
    *is_wildcard = FALSE;

    // SOCK_ADDR hook clients must always provide data.
    if (client_data == NULL) {
        NET_EBPF_EXT_LOG_MESSAGE(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
            "Attach denied. client data not provided.");
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    if (client_data->header.size > 0) {
        if ((client_data->header.size != sizeof(uint32_t)) || (client_data->data == NULL)) {
            NET_EBPF_EXT_LOG_MESSAGE(
                NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
                NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
                "Attach denied. Invalid client data.");
            result = EBPF_INVALID_ARGUMENT;
            goto Exit;
        }
        compartment_id = *(uint32_t*)client_data->data;
        if (compartment_id == UNSPECIFIED_COMPARTMENT_ID) {
            *is_wildcard = TRUE;
        }
    } else {
        // If the client did not specify any attach parameters, we treat that as a wildcard compartment id.
        *is_wildcard = TRUE;
    }

Exit:
    return result;
}

static bool
_net_ebpf_ext_is_cgroup_connect_attach_type(_In_ const ebpf_attach_type_t* attach_type)
{
    return (
        memcmp(attach_type, &EBPF_ATTACH_TYPE_CGROUP_INET4_CONNECT, sizeof(GUID)) == 0 ||
        memcmp(attach_type, &EBPF_ATTACH_TYPE_CGROUP_INET6_CONNECT, sizeof(GUID)) == 0);
}

//
// NMR Registration Helper Routines.
//

static ebpf_result_t
_net_ebpf_extension_sock_addr_create_filter_context(
    _In_ const net_ebpf_extension_hook_client_t* attaching_client,
    _In_ const net_ebpf_extension_hook_provider_t* provider_context,
    _Outptr_ net_ebpf_extension_wfp_filter_context_t** filter_context)
{
    NTSTATUS status;
    ebpf_result_t result = EBPF_SUCCESS;
    net_ebpf_extension_sock_addr_wfp_filter_context_t* local_filter_context = NULL;
    uint32_t compartment_id = UNSPECIFIED_COMPARTMENT_ID;
    FWPM_FILTER_CONDITION condition = {0};
    net_ebpf_extension_wfp_filter_parameters_array_t* filter_parameters_array = NULL;
    const ebpf_extension_data_t* client_data = net_ebpf_extension_hook_client_get_client_data(attaching_client);

    if (client_data->header.size > 0) {
        // Note: No need to validate the client data here, as it has already been validated by the caller.
        compartment_id = *(uint32_t*)client_data->data;
    }

    // Set compartment id (if not UNSPECIFIED_COMPARTMENT_ID) as WFP filter condition.
    if (compartment_id != UNSPECIFIED_COMPARTMENT_ID) {
        condition.fieldKey = FWPM_CONDITION_COMPARTMENT_ID;
        condition.matchType = FWP_MATCH_EQUAL;
        condition.conditionValue.type = FWP_UINT32;
        condition.conditionValue.uint32 = compartment_id;
    }

    // Get the WFP filter parameters for this hook type.
    filter_parameters_array =
        (net_ebpf_extension_wfp_filter_parameters_array_t*)net_ebpf_extension_hook_provider_get_custom_data(
            provider_context);
    ASSERT(filter_parameters_array != NULL);

    result = net_ebpf_extension_wfp_filter_context_create(
        sizeof(net_ebpf_extension_sock_addr_wfp_filter_context_t),
        attaching_client,
        provider_context,
        (net_ebpf_extension_wfp_filter_context_t**)&local_filter_context);
    NET_EBPF_EXT_BAIL_ON_ERROR_RESULT(result);

    local_filter_context->redirect_handle = NULL;
    local_filter_context->compartment_id = compartment_id;

    local_filter_context->base.filter_ids_count = filter_parameters_array->count;

    // Special case of connect_redirect. If the attach type is v4, set v4_attach_type in the filter
    // context to TRUE.
    if (memcmp(filter_parameters_array->attach_type, &EBPF_ATTACH_TYPE_CGROUP_INET4_CONNECT, sizeof(GUID)) == 0) {
        local_filter_context->v4_attach_type = TRUE;
    }

    // Allocate redirect handle for this filter context, only in the case of INET*_CONNECT attach types.
    if (_net_ebpf_ext_is_cgroup_connect_attach_type(filter_parameters_array->attach_type)) {
        status = FwpsRedirectHandleCreate(
            &EBPF_HOOK_ALE_CONNECT_REDIRECT_PROVIDER, 0, &local_filter_context->redirect_handle);
        if (!NT_SUCCESS(status)) {
            NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(
                NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR, "FwpsRedirectHandleCreate", status);
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
        (net_ebpf_extension_wfp_filter_context_t*)local_filter_context,
        &local_filter_context->base.filter_ids);
    NET_EBPF_EXT_BAIL_ON_ERROR_RESULT(result);

    *filter_context = (net_ebpf_extension_wfp_filter_context_t*)local_filter_context;
    local_filter_context = NULL;

Exit:
    CLEAN_UP_SOCK_ADDR_FILTER_CONTEXT(local_filter_context);

    NET_EBPF_EXT_RETURN_RESULT(result);
}

static void
_net_ebpf_extension_sock_addr_delete_filter_context(
    _In_opt_ _Frees_ptr_opt_ net_ebpf_extension_wfp_filter_context_t* filter_context)
{
    net_ebpf_extension_sock_addr_wfp_filter_context_t* sock_addr_filter_context = NULL;

    NET_EBPF_EXT_LOG_ENTRY();

    if (filter_context == NULL) {
        goto Exit;
    }
    sock_addr_filter_context = (net_ebpf_extension_sock_addr_wfp_filter_context_t*)filter_context;

    net_ebpf_extension_delete_wfp_filters(filter_context->filter_ids_count, filter_context->filter_ids);
    if (sock_addr_filter_context->redirect_handle != NULL) {
        FwpsRedirectHandleDestroy(sock_addr_filter_context->redirect_handle);
    }
    net_ebpf_extension_wfp_filter_context_cleanup(filter_context);

Exit:
    NET_EBPF_EXT_LOG_EXIT();
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

void
_net_ebpf_ext_uninitialize_blocked_connection_contexts()
{
    KIRQL old_irql = ExAcquireSpinLockExclusive(&_net_ebpf_ext_sock_addr_blocked_contexts.lock);

    // Clean up all in use connect contexts.
    _net_ebpf_ext_purge_blocked_connect_contexts(true);

    // Clean up pre-allocated connect contexts.
    while (!IsListEmpty(&_net_ebpf_ext_sock_addr_blocked_contexts.low_memory_free_context_list)) {
        PLIST_ENTRY entry = RemoveHeadList(&_net_ebpf_ext_sock_addr_blocked_contexts.low_memory_free_context_list);
        net_ebpf_extension_connection_context_t* context =
            CONTAINING_RECORD(entry, net_ebpf_extension_connection_context_t, list_entry);
        ExFreePool(context);
    }

    ExReleaseSpinLockExclusive(&_net_ebpf_ext_sock_addr_blocked_contexts.lock, old_irql);
}

_Function_class_(RTL_AVL_COMPARE_ROUTINE) static RTL_GENERIC_COMPARE_RESULTS
    _net_ebpf_sock_addr_blocked_context_avl_compare_routine(
        _In_ RTL_AVL_TABLE* table, _In_ PVOID first, _In_ PVOID second)
{
    UNREFERENCED_PARAMETER(table);

    int result = memcmp(first, second, EBPF_OFFSET_OF(net_ebpf_extension_connection_context_t, timestamp));
    if (result < 0) {
        return GenericLessThan;
    } else if (result > 0) {
        return GenericGreaterThan;
    } else {
        return GenericEqual;
    }
}

_Function_class_(RTL_AVL_ALLOCATE_ROUTINE) static PVOID
    _net_ebpf_sock_addr_blocked_context_avl_allocate_routine(_In_ RTL_AVL_TABLE* table, _In_ CLONG buffer_size)
{
    UNREFERENCED_PARAMETER(table);

    PVOID buffer = ExAllocatePoolUninitialized(NonPagedPoolNx, buffer_size, NET_EBPF_EXTENSION_POOL_TAG);
    if (buffer) {
        memset(buffer, 0, buffer_size);
    }
    return buffer;
}

_Function_class_(RTL_AVL_FREE_ROUTINE) static VOID
    _net_ebpf_sock_addr_blocked_context_avl_free_routine(_In_ RTL_AVL_TABLE* table, _In_ PVOID buffer)
{
    UNREFERENCED_PARAMETER(table);

    ExFreePool(buffer);
}

static NTSTATUS
_net_ebpf_sock_addr_initialize_blocked_connection_contexts()
{
    NTSTATUS status = STATUS_SUCCESS;

    RtlInitializeGenericTableAvl(
        &_net_ebpf_ext_sock_addr_blocked_contexts.blocked_context_table,
        _net_ebpf_sock_addr_blocked_context_avl_compare_routine,
        _net_ebpf_sock_addr_blocked_context_avl_allocate_routine,
        _net_ebpf_sock_addr_blocked_context_avl_free_routine,
        NULL);

    InitializeListHead(&_net_ebpf_ext_sock_addr_blocked_contexts.blocked_context_lru_list);
    InitializeListHead(&_net_ebpf_ext_sock_addr_blocked_contexts.low_memory_free_context_list);
    InitializeListHead(&_net_ebpf_ext_sock_addr_blocked_contexts.low_memory_blocked_context_list);

    // Pre-allocate entries for use under low memory conditions.
    for (int32_t i = 0; i < LOW_MEMORY_CONNECTION_CONTEXT_COUNT; i++) {
        net_ebpf_extension_connection_context_t* context =
            (net_ebpf_extension_connection_context_t*)ExAllocatePoolUninitialized(
                NonPagedPoolNx, sizeof(net_ebpf_extension_connection_context_t), NET_EBPF_EXTENSION_POOL_TAG);
        if (!context) {
            status = STATUS_NO_MEMORY;
            goto Exit;
        }
        InsertHeadList(&_net_ebpf_ext_sock_addr_blocked_contexts.low_memory_free_context_list, &context->list_entry);
    }

Exit:
    if (!NT_SUCCESS(status)) {
        _net_ebpf_ext_uninitialize_blocked_connection_contexts();
    }
    return status;
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
    uint64_t transport_endpoint_handle,
    _In_ const bpf_sock_addr_t* sock_addr_ctx,
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

_Requires_exclusive_lock_held_(
    _net_ebpf_ext_sock_addr_blocked_contexts
        .lock) static bool _net_ebpf_ext_find_and_remove_connection_context_locked(_In_
                                                                                       net_ebpf_extension_connection_context_t*
                                                                                           context)
{
    bool entry_found = false;
    // Check the hash table for the entry.
    net_ebpf_extension_connection_context_t* found_context =
        (net_ebpf_extension_connection_context_t*)RtlLookupElementGenericTableAvl(
            &_net_ebpf_ext_sock_addr_blocked_contexts.blocked_context_table, context);
    if (found_context != NULL) {
        entry_found = true;
        RemoveEntryList(&found_context->list_entry);
        uint64_t transport_endpoint_handle = found_context->transport_endpoint_handle;
        // Delete should succeed as the entry was just found in the lookup.
        BOOLEAN result =
            RtlDeleteElementGenericTableAvl(&_net_ebpf_ext_sock_addr_blocked_contexts.blocked_context_table, context);
        ebpf_assert(result);
        _net_ebpf_ext_sock_addr_blocked_contexts.blocked_context_count--;
        NET_EBPF_EXT_LOG_MESSAGE_UINT64(
            NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
            "_net_ebpf_ext_find_and_remove_connection_context_locked: Delete",
            transport_endpoint_handle);
    } else {
        // The entry was not found in the hash table. Check the low-memory list to see if the entry is there.
        LIST_ENTRY* entry = _net_ebpf_ext_sock_addr_blocked_contexts.low_memory_blocked_context_list.Flink;
        while (entry != &_net_ebpf_ext_sock_addr_blocked_contexts.low_memory_blocked_context_list) {
            net_ebpf_extension_connection_context_t* connection_context =
                CONTAINING_RECORD(entry, net_ebpf_extension_connection_context_t, list_entry);
            if (memcmp(
                    context, connection_context, EBPF_OFFSET_OF(net_ebpf_extension_connection_context_t, timestamp)) ==
                0) {
                // Found matching entry. Remove it from the list and return it to the free list, and then return a block
                // verdict.
                RemoveEntryList(&connection_context->list_entry);
                InsertHeadList(
                    &_net_ebpf_ext_sock_addr_blocked_contexts.low_memory_free_context_list,
                    &connection_context->list_entry);
                _net_ebpf_ext_sock_addr_blocked_contexts.low_memory_blocked_context_count--;
                entry_found = true;
                break;
            }
            entry = entry->Flink;
        }
    }

    return entry_found;
}

static bool
_net_ebpf_ext_find_and_remove_connection_context(
    uint64_t transport_endpoint_handle, _In_ const bpf_sock_addr_t* sock_addr_ctx)
{
    KIRQL old_irql;
    bool entry_found = false;
    net_ebpf_extension_connection_context_t local_connection_context = {0};

    _net_ebpf_extension_connection_context_initialize(
        transport_endpoint_handle, sock_addr_ctx, 0, &local_connection_context);

    old_irql = ExAcquireSpinLockExclusive(&_net_ebpf_ext_sock_addr_blocked_contexts.lock);
    entry_found = _net_ebpf_ext_find_and_remove_connection_context_locked(&local_connection_context);
    ExReleaseSpinLockExclusive(&_net_ebpf_ext_sock_addr_blocked_contexts.lock, old_irql);

    return entry_found;
}

_Requires_exclusive_lock_held_(_net_ebpf_ext_sock_addr_blocked_contexts
                                   .lock) static void _net_ebpf_ext_purge_blocked_connect_contexts(bool delete_all)
{
    uint64_t expiry_time = CONVERT_100NS_UNITS_TO_MS(KeQueryInterruptTime()) - EXPIRY_TIME;

    // Free entries from the LRU list. These entries should also be removed from the table.
    LIST_ENTRY* list_entry = _net_ebpf_ext_sock_addr_blocked_contexts.blocked_context_lru_list.Blink;
    while (list_entry != &_net_ebpf_ext_sock_addr_blocked_contexts.blocked_context_lru_list) {
        net_ebpf_extension_connection_context_t* entry =
            CONTAINING_RECORD(list_entry, net_ebpf_extension_connection_context_t, list_entry);
        // Move pointer to next entry prior to removing the entry.
        list_entry = list_entry->Blink;

        if (!delete_all && entry->timestamp > expiry_time) {
            break;
        }

#pragma warning(suppress : 6001) /* entry and list entry are non-null */
        RemoveEntryList(&entry->list_entry);
        uint64_t transport_endpoint_handle = entry->transport_endpoint_handle;
        BOOLEAN result =
            RtlDeleteElementGenericTableAvl(&_net_ebpf_ext_sock_addr_blocked_contexts.blocked_context_table, entry);
        ebpf_assert(result);
        entry = NULL;
        _net_ebpf_ext_sock_addr_blocked_contexts.blocked_context_count--;
        NET_EBPF_EXT_LOG_MESSAGE_UINT64(
            NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
            "_net_ebpf_ext_purge_block_connect_contexts: Delete",
            transport_endpoint_handle);
    }

    // Free entries from low-memory list.
    list_entry = _net_ebpf_ext_sock_addr_blocked_contexts.low_memory_blocked_context_list.Blink;
    while (list_entry != &_net_ebpf_ext_sock_addr_blocked_contexts.low_memory_blocked_context_list) {
        net_ebpf_extension_connection_context_t* entry =
            CONTAINING_RECORD(list_entry, net_ebpf_extension_connection_context_t, list_entry);
        if (!delete_all && entry->timestamp > expiry_time) {
            break;
        }

#pragma warning(suppress : 6001) /* entry and list entry are non-null */
        list_entry = list_entry->Blink;
        RemoveEntryList(&entry->list_entry);

        if (delete_all) {
            // Free the memory.
            ExFreePool(entry);
        } else {
            // Return the entry to the free list.
            InsertHeadList(&_net_ebpf_ext_sock_addr_blocked_contexts.low_memory_free_context_list, &entry->list_entry);
        }
        _net_ebpf_ext_sock_addr_blocked_contexts.low_memory_blocked_context_count--;
    }

    NET_EBPF_EXT_LOG_MESSAGE_UINT64(
        NET_EBPF_EXT_TRACELOG_LEVEL_INFO,
        NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
        "_net_ebpf_ext_purge_block_connect_contexts",
        _net_ebpf_ext_sock_addr_blocked_contexts.blocked_context_count);
}

_Requires_exclusive_lock_held_(_net_ebpf_ext_sock_addr_blocked_contexts.lock) static ebpf_result_t
    _net_ebpf_ext_insert_connection_context_to_low_memory_list(
        _In_ uint64_t transport_endpoint_handle, _In_ const bpf_sock_addr_t* sock_addr_ctx)
{
    ebpf_result_t result = EBPF_SUCCESS;
    PLIST_ENTRY entry = NULL;
    net_ebpf_extension_connection_context_t* blocked_connection_context = NULL;

    if (IsListEmpty(&_net_ebpf_ext_sock_addr_blocked_contexts.low_memory_free_context_list)) {
        NET_EBPF_EXT_BAIL_ON_ERROR_RESULT(EBPF_NO_MEMORY);
    }

    // Retrieve an entry from the pre-allocated list.
    entry = RemoveHeadList(&_net_ebpf_ext_sock_addr_blocked_contexts.low_memory_free_context_list);
    blocked_connection_context = CONTAINING_RECORD(entry, net_ebpf_extension_connection_context_t, list_entry);
    memset(blocked_connection_context, 0, sizeof(net_ebpf_extension_connection_context_t));

    _net_ebpf_extension_connection_context_initialize(
        transport_endpoint_handle,
        sock_addr_ctx,
        CONNECTION_CONTEXT_INITIALIZATION_SET_TIMESTAMP,
        blocked_connection_context);

    // Insert into the blocked context list.
    InsertHeadList(
        &_net_ebpf_ext_sock_addr_blocked_contexts.low_memory_blocked_context_list,
        &blocked_connection_context->list_entry);
    _net_ebpf_ext_sock_addr_blocked_contexts.low_memory_blocked_context_count++;
    InterlockedIncrement(&_net_ebpf_ext_statistics.low_memory_context_count);

Exit:
    return result;
}

static ebpf_result_t
_net_ebpf_ext_insert_connection_context_to_list(
    _In_ uint64_t transport_endpoint_handle, _In_ const bpf_sock_addr_t* sock_addr_ctx)
{
    ebpf_result_t result = EBPF_SUCCESS;
    KIRQL old_irql = PASSIVE_LEVEL;
    net_ebpf_extension_connection_context_t blocked_connection_context = {0};
    net_ebpf_extension_connection_context_t* new_context = NULL;

    _net_ebpf_extension_connection_context_initialize(
        transport_endpoint_handle,
        sock_addr_ctx,
        CONNECTION_CONTEXT_INITIALIZATION_SET_TIMESTAMP,
        &blocked_connection_context);

    old_irql = ExAcquireSpinLockExclusive(&_net_ebpf_ext_sock_addr_blocked_contexts.lock);

    // Remove the context if it exists.
    _net_ebpf_ext_find_and_remove_connection_context_locked(&blocked_connection_context);

    // Insert into table.
    new_context = (net_ebpf_extension_connection_context_t*)RtlInsertElementGenericTableAvl(
        &_net_ebpf_ext_sock_addr_blocked_contexts.blocked_context_table,
        &blocked_connection_context,
        sizeof(blocked_connection_context),
        NULL);
    NET_EBPF_EXT_BAIL_ON_ALLOC_FAILURE_RESULT(
        NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR, new_context, "blocked_connection", result);

    // Successfully inserted into the table. Also insert into the LRU list to ensure
    // entries are not leaked.
    InsertHeadList(&_net_ebpf_ext_sock_addr_blocked_contexts.blocked_context_lru_list, &new_context->list_entry);
    _net_ebpf_ext_sock_addr_blocked_contexts.blocked_context_count++;
    InterlockedIncrement(&_net_ebpf_ext_statistics.block_connection_count);
    NET_EBPF_EXT_LOG_MESSAGE_UINT64(
        NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
        NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
        "_net_ebpf_ext_insert_connection_context_to_list: Insert",
        transport_endpoint_handle);

Exit:
    if (result != EBPF_SUCCESS) {
        // If any failure occurred, attempt to use low memory list instead.
        result = _net_ebpf_ext_insert_connection_context_to_low_memory_list(transport_endpoint_handle, sock_addr_ctx);
    }

    // Purge stale entries from the list.
    _net_ebpf_ext_purge_blocked_connect_contexts(false);
    ExReleaseSpinLockExclusive(&_net_ebpf_ext_sock_addr_blocked_contexts.lock, old_irql);

    NET_EBPF_EXT_RETURN_RESULT(result);
}

NTSTATUS
net_ebpf_ext_sock_addr_register_providers()
{
    NTSTATUS status = STATUS_SUCCESS;
    bool blocked_connection_contexts_initialized = false;
    bool is_cgroup_connect_attach_type = false;

    NET_EBPF_EXT_LOG_ENTRY();

    const net_ebpf_extension_program_info_provider_parameters_t program_info_provider_parameters = {
        &_ebpf_sock_addr_program_info_provider_moduleid, &_ebpf_sock_addr_program_data};

    const net_ebpf_extension_hook_provider_dispatch_table_t connect_dispatch_table = {
        .create_filter_context = _net_ebpf_extension_sock_addr_create_filter_context,
        .delete_filter_context = _net_ebpf_extension_sock_addr_delete_filter_context,
        .validate_client_data = _net_ebpf_extension_sock_addr_validate_client_data,
        .process_verdict = _net_ebpf_extension_sock_addr_process_verdict,
    };

    const net_ebpf_extension_hook_provider_dispatch_table_t recv_accept_dispatch_table = {
        .create_filter_context = _net_ebpf_extension_sock_addr_create_filter_context,
        .delete_filter_context = _net_ebpf_extension_sock_addr_delete_filter_context,
        .validate_client_data = _net_ebpf_extension_sock_addr_validate_client_data,
    };

    status = _net_ebpf_sock_addr_create_security_descriptor();
    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_LOG_MESSAGE_NTSTATUS(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
            "_net_ebpf_sock_addr_create_security_descriptor failed.",
            status);
        goto Exit;
    }

    status = _net_ebpf_sock_addr_initialize_blocked_connection_contexts();
    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_LOG_MESSAGE_NTSTATUS(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
            "_net_ebpf_sock_addr_initialize_blocked_connection_contexts failed.",
            status);
        goto Exit;
    }
    blocked_connection_contexts_initialized = true;

    status = net_ebpf_extension_program_info_provider_register(
        &program_info_provider_parameters, &_ebpf_sock_addr_program_info_provider_context);
    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_LOG_MESSAGE_NTSTATUS(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
            "net_ebpf_extension_program_info_provider_register failed.",
            status);
        goto Exit;
    }

    for (int i = 0; i < NET_EBPF_SOCK_ADDR_HOOK_PROVIDER_COUNT; i++) {
        const net_ebpf_extension_hook_provider_parameters_t hook_provider_parameters = {
            &_ebpf_sock_addr_hook_provider_moduleid[i], &_net_ebpf_sock_addr_hook_provider_data[i]};

        _net_ebpf_sock_addr_hook_provider_data[i].header.version = EBPF_ATTACH_PROVIDER_DATA_CURRENT_VERSION;
        _net_ebpf_sock_addr_hook_provider_data[i].header.size = EBPF_ATTACH_PROVIDER_DATA_CURRENT_VERSION_SIZE;
        _net_ebpf_sock_addr_hook_provider_data[i].header.total_size =
            EBPF_ATTACH_PROVIDER_DATA_CURRENT_VERSION_TOTAL_SIZE;
        _net_ebpf_sock_addr_hook_provider_data[i].supported_program_type = EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR;
        _net_ebpf_sock_addr_hook_provider_data[i].bpf_attach_type =
            (bpf_attach_type_t)_net_ebpf_extension_sock_addr_bpf_attach_types[i];
        _net_ebpf_sock_addr_hook_provider_data[i].link_type = BPF_LINK_TYPE_CGROUP;

        // Set the attach type as the provider module id.
        _ebpf_sock_addr_hook_provider_moduleid[i].Length = sizeof(NPI_MODULEID);
        _ebpf_sock_addr_hook_provider_moduleid[i].Type = MIT_GUID;
        _ebpf_sock_addr_hook_provider_moduleid[i].Guid = *_net_ebpf_extension_sock_addr_attach_types[i];

        is_cgroup_connect_attach_type =
            _net_ebpf_ext_is_cgroup_connect_attach_type(_net_ebpf_extension_sock_addr_attach_types[i]);

        const net_ebpf_extension_hook_provider_dispatch_table_t* dispatch_table =
            is_cgroup_connect_attach_type ? &connect_dispatch_table : &recv_accept_dispatch_table;

        // Register the provider context and pass the pointer to the WFP filter parameters
        // corresponding to this hook type as custom data.
        status = net_ebpf_extension_hook_provider_register(
            &hook_provider_parameters,
            dispatch_table,
            is_cgroup_connect_attach_type ? ATTACH_CAPABILITY_MULTI_ATTACH_WITH_WILDCARD
                                          : ATTACH_CAPABILITY_SINGLE_ATTACH_PER_HOOK,
            &_net_ebpf_extension_sock_addr_wfp_filter_parameters[i],
            &_ebpf_sock_addr_hook_provider_context[i]);
        if (!NT_SUCCESS(status)) {
            NET_EBPF_EXT_LOG_MESSAGE_NTSTATUS(
                NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
                NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
                "net_ebpf_extension_hook_provider_register failed.",
                status);
        }
    }

Exit:
    if (!NT_SUCCESS(status)) {
        if (blocked_connection_contexts_initialized) {
            net_ebpf_ext_sock_addr_unregister_providers();
        }
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

    _net_ebpf_ext_uninitialize_blocked_connection_contexts();
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

    sock_addr_ctx->hook_id = hook_id;
    sock_addr_ctx->transport_endpoint_handle = incoming_metadata_values->transportEndpointHandle;

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

static void
_net_ebpf_ext_sock_addr_redirected(
    _In_ const bpf_sock_addr_t* original_context,
    _In_ const bpf_sock_addr_t* redirected_context,
    _Out_ bool* redirected,
    _Out_ bool* address_changed)
{
    *redirected = FALSE;
    *address_changed = !_net_ebpf_ext_compare_destination_address(redirected_context, original_context);
    if (redirected_context->user_port != original_context->user_port || *address_changed) {
        *redirected = TRUE;
    }
}

static bool
_net_ebpf_extension_sock_addr_process_verdict(_Inout_ void* program_context, int program_verdict)
{
    // Check if the updated context is same as the original context.
    // If it has been modified, then the verdict is to stop processing.

    bpf_sock_addr_t* sock_addr_ctx = (bpf_sock_addr_t*)program_context;
    net_ebpf_sock_addr_t* context = CONTAINING_RECORD(sock_addr_ctx, net_ebpf_sock_addr_t, base);
    bpf_sock_addr_t* original_context = context->original_context;
    bpf_sock_addr_t local_context = *sock_addr_ctx;
    bool redirected = FALSE;
    bool address_changed = FALSE;

    if (context->v4_mapped) {
        // If it is a v4-mapped address, convert it to v6 before comparing.
        local_context.family = AF_INET6;
        IN_ADDR v4_address = *((IN_ADDR*)&local_context.user_ip4);
        IN6_SET_ADDR_V4MAPPED((IN6_ADDR*)&local_context.user_ip6, (IN_ADDR*)&v4_address);
    }

    _net_ebpf_ext_sock_addr_redirected(original_context, &local_context, &redirected, &address_changed);
    context->redirected = redirected;
    context->address_changed = address_changed;

    if (redirected || program_verdict == BPF_SOCK_ADDR_VERDICT_REJECT) {
        return FALSE;
    }

    return TRUE;
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
    net_ebpf_sock_addr_t net_ebpf_sock_addr_ctx = {0};
    bpf_sock_addr_t* sock_addr_ctx = &net_ebpf_sock_addr_ctx.base;
    uint32_t compartment_id = UNSPECIFIED_COMPARTMENT_ID;
    ebpf_result_t program_result;

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

    // Note: This is intentionally not guarded by a lock as this is opportunistically checking if all the
    // clients have detached and the filter context is being deleted.
    if (filter_context->base.context_deleting) {
        NET_EBPF_EXT_LOG_MESSAGE_NTSTATUS(
            NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
            "net_ebpf_extension_sock_addr_authorize_recv_accept_classify - Client detach detected.",
            STATUS_INVALID_PARAMETER);
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

    program_result = net_ebpf_extension_hook_invoke_programs(sock_addr_ctx, &filter_context->base, &result);
    if (program_result == EBPF_OBJECT_NOT_FOUND) {
        // No eBPF program is attached to this filter.
        goto Exit;
    } else if (program_result != EBPF_SUCCESS) {
        // We failed to invoke at least one program in the chain, block the request.
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

    // If a context was found and removed, then the program issued a reject verdict.
    if (_net_ebpf_ext_find_and_remove_connection_context(
            incoming_metadata_values->transportEndpointHandle, sock_addr_ctx)) {
        verdict = BPF_SOCK_ADDR_VERDICT_REJECT;
    } else {
        verdict = BPF_SOCK_ADDR_VERDICT_PROCEED;
    }

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
    _Inout_ FWPS_CLASSIFY_OUT* classify_output)
{
    NTSTATUS status = STATUS_SUCCESS;
    FWPS_CONNECT_REQUEST* connect_request = NULL;
    BOOLEAN commit_layer_data = FALSE;
    net_ebpf_sock_addr_t* sock_addr_ctx = CONTAINING_RECORD(redirected_context, net_ebpf_sock_addr_t, base);

    // Check if destination IP and/or port have been modified.
    if (sock_addr_ctx->redirected) {
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
        if (sock_addr_ctx->address_changed) {
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

        connect_request->localRedirectContext = sock_addr_ctx->redirect_context;
        connect_request->localRedirectContextSize = sock_addr_ctx->redirect_context_size;
        // Ownership transferred to WFP.
        sock_addr_ctx->redirect_context = NULL;
        sock_addr_ctx->redirect_context_size = 0;
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
    bool reauthorization = FALSE;

    UNREFERENCED_PARAMETER(layer_data);
    UNREFERENCED_PARAMETER(flow_context);

    if ((classify_output->rights & FWPS_RIGHT_ACTION_WRITE) == 0) {
        // A callout with higher weight has revoked the write permission. Bail out.
        NET_EBPF_EXT_LOG_MESSAGE(
            NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
            "No \"write\" right; exiting.");
        verdict = BPF_SOCK_ADDR_VERDICT_PROCEED;
        goto Exit;
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

    // Note: This is intentionally not guarded by a lock as this is opportunistically checking if all the
    // clients have detached and the filter context is being deleted.
    if (filter_context->base.context_deleting) {
        NET_EBPF_EXT_LOG_MESSAGE_NTSTATUS(
            NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
            "net_ebpf_extension_sock_addr_redirect_connection_classify - Client detach detected.",
            STATUS_INVALID_PARAMETER);
        verdict = BPF_SOCK_ADDR_VERDICT_PROCEED;
        goto Exit;
    }

    // Populate the sock_addr context with WFP classify input fields.
    _net_ebpf_extension_sock_addr_copy_wfp_connection_fields(
        incoming_fixed_values, incoming_metadata_values, &net_ebpf_sock_addr_ctx);

    // In case of re-authorization, the eBPF programs have already inspected the connection.
    // Skip invoking the program(s) again. In this case the verdict is always to proceed (terminating).
    if (net_ebpf_sock_addr_ctx.flags & FWP_CONDITION_FLAG_IS_REAUTHORIZE) {
        verdict = BPF_SOCK_ADDR_VERDICT_PROCEED;
        reauthorization = TRUE;
        NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
            "Reauthorize connection: skip.",
            filter->filterId,
            (uint64_t)sock_addr_ctx->compartment_id);
        goto Exit;
    }

    memcpy(&sock_addr_ctx_original, sock_addr_ctx, sizeof(sock_addr_ctx_original));
    net_ebpf_sock_addr_ctx.original_context = &sock_addr_ctx_original;

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
    net_ebpf_sock_addr_ctx.v4_mapped = v4_mapped;

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

    result = net_ebpf_extension_hook_expand_stack_and_invoke_programs(sock_addr_ctx, &filter_context->base, &verdict);
    if (result == EBPF_OBJECT_NOT_FOUND) {
        // No eBPF program is attached to this filter.
        verdict = BPF_SOCK_ADDR_VERDICT_PROCEED;
    } else if (result != EBPF_SUCCESS) {
        // We failed to invoke at least one program in the chain, block the request.
        verdict = BPF_SOCK_ADDR_VERDICT_REJECT;
    }

    if (verdict == BPF_SOCK_ADDR_VERDICT_REJECT) {
        NET_EBPF_EXT_LOG_MESSAGE(
            NET_EBPF_EXT_TRACELOG_LEVEL_WARNING,
            NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
            "cgroup_sock_addr eBPF program returned REJECT verdict.");
        goto Exit;
    }

    redirected = net_ebpf_sock_addr_ctx.redirected;

    if (verdict == BPF_SOCK_ADDR_VERDICT_PROCEED) {
        if (v4_mapped) {
            // Revert back the sock_addr_ctx to v4-mapped v6 address for connection-redirection processing.
            sock_addr_ctx->family = AF_INET6;
            IN_ADDR v4_address = *((IN_ADDR*)&sock_addr_ctx->user_ip4);
            IN6_SET_ADDR_V4MAPPED((IN6_ADDR*)&sock_addr_ctx->user_ip6, (IN_ADDR*)&v4_address);
        }
        status = _net_ebpf_ext_process_redirect_verdict(
            &sock_addr_ctx_original, sock_addr_ctx, filter, classify_handle, redirect_handle, classify_output);
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
        _net_ebpf_ext_insert_connection_context_to_list(
            incoming_metadata_values->transportEndpointHandle, sock_addr_ctx);
    } else if (!reauthorization) {
        // Remove any 'stale' connection context if found.
        // A stale context is expected in the case of connected UDP, where the connect()
        // call results in WFP invoking the callout at the connect_redirect layer, and the
        // send() call results in WFP invoking the callout at the connect_redirect layer (again),
        // followed by the connect layer.
        _net_ebpf_ext_find_and_remove_connection_context(
            incoming_metadata_values->transportEndpointHandle, sock_addr_ctx);
    }

    // Callout at CONNECT_REDIRECT layer always returns WFP action PERMIT / CONTINUE.
    // If the connection was redirected or blocked, make the action TERMINATING.
    if (reauthorization || redirected || verdict == BPF_SOCK_ADDR_VERDICT_REJECT) {
        classify_output->actionType = FWP_ACTION_PERMIT;
    } else {
        classify_output->actionType = FWP_ACTION_CONTINUE;
    }

    if (classify_handle_acquired) {
        FwpsReleaseClassifyHandle(classify_handle);
    }

    if (net_ebpf_sock_addr_ctx.redirect_context != NULL) {
        ExFreePool(net_ebpf_sock_addr_ctx.redirect_context);
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
    net_ebpf_sock_addr_t* ctx = NULL;
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

    ctx = (net_ebpf_sock_addr_t*)ExAllocatePoolUninitialized(
        NonPagedPoolNx, sizeof(net_ebpf_sock_addr_t), NET_EBPF_EXTENSION_POOL_TAG);
    NET_EBPF_EXT_BAIL_ON_ALLOC_FAILURE_RESULT(NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR, ctx, "sock_addr_ctx", result);

    sock_addr_ctx = &ctx->base;
    memcpy(sock_addr_ctx, context_in, sizeof(bpf_sock_addr_t));

    result = EBPF_SUCCESS;
    *context = sock_addr_ctx;

    ctx = NULL;

Exit:
    if (ctx) {
        ExFreePool(ctx);
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
    net_ebpf_sock_addr_t* sock_addr_ctx = NULL;

    UNREFERENCED_PARAMETER(data_out);
    *data_size_out = 0;

    if (!context) {
        return;
    }
    sock_addr_ctx = CONTAINING_RECORD(context, net_ebpf_sock_addr_t, base);

    if (context_out != NULL && *context_size_out >= sizeof(bpf_sock_addr_t)) {
        memcpy(context_out, context, sizeof(bpf_sock_addr_t));
        *context_size_out = sizeof(bpf_sock_addr_t);
    } else {
        *context_size_out = 0;
    }

    if (sock_addr_ctx) {
        ExFreePool(sock_addr_ctx);
    }
    NET_EBPF_EXT_LOG_EXIT();
}
