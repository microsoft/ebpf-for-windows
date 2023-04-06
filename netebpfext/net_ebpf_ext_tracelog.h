// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

TRACELOGGING_DECLARE_PROVIDER(net_ebpf_ext_tracelog_provider);

NTSTATUS
net_ebpf_ext_trace_initiate();

void
net_ebpf_ext_trace_terminate();

#define NET_EBPF_EXT_TRACELOG_EVENT_SUCCESS "NetEbpfExtSuccess"
#define NET_EBPF_EXT_TRACELOG_EVENT_RETURN "NetEbpfExtReturn"
#define NET_EBPF_EXT_TRACELOG_EVENT_GENERIC_ERROR "NetEbpfExtGenericError"
#define NET_EBPF_EXT_TRACELOG_EVENT_GENERIC_MESSAGE "NetEbpfExtGenericMessage"
#define NET_EBPF_EXT_TRACELOG_EVENT_API_ERROR "NetEbpfExtApiError"

#define NET_EBPF_EXT_TRACELOG_KEYWORD_FUNCTION_ENTRY_EXIT 0x1
#define NET_EBPF_EXT_TRACELOG_KEYWORD_BASE 0x2
#define NET_EBPF_EXT_TRACELOG_KEYWORD_ERROR 0x4
#define NET_EBPF_EXT_TRACELOG_KEYWORD_XDP 0x8
#define NET_EBPF_EXT_TRACELOG_KEYWORD_BIND 0x10
#define NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR 0x20
#define NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_OPS 0x40

#define NET_EBPF_EXT_TRACELOG_LEVEL_LOG_ALWAYS WINEVENT_LEVEL_LOG_ALWAYS
#define NET_EBPF_EXT_TRACELOG_LEVEL_CRITICAL WINEVENT_LEVEL_CRITICAL
#define NET_EBPF_EXT_TRACELOG_LEVEL_ERROR WINEVENT_LEVEL_ERROR
#define NET_EBPF_EXT_TRACELOG_LEVEL_WARNING WINEVENT_LEVEL_WARNING
#define NET_EBPF_EXT_TRACELOG_LEVEL_INFO WINEVENT_LEVEL_INFO
#define NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE WINEVENT_LEVEL_VERBOSE

#define NET_EBPF_EXT_LOG_FUNCTION_SUCCESS()                      \
    TraceLoggingWrite(                                           \
        net_ebpf_ext_tracelog_provider,                          \
        NET_EBPF_EXT_TRACELOG_EVENT_SUCCESS,                     \
        TraceLoggingLevel(WINEVENT_LEVEL_VERBOSE),               \
        TraceLoggingKeyword(NET_EBPF_EXT_TRACELOG_KEYWORD_BASE), \
        TraceLoggingString(__FUNCTION__ " returned success", "Message"));

#define NET_EBPF_EXT_LOG_FUNCTION_ERROR(result)                             \
    TraceLoggingWrite(                                                      \
        net_ebpf_ext_tracelog_provider,                                     \
        NET_EBPF_EXT_TRACELOG_EVENT_GENERIC_ERROR,                          \
        TraceLoggingLevel(WINEVENT_LEVEL_ERROR),                            \
        TraceLoggingKeyword(NET_EBPF_EXT_TRACELOG_KEYWORD_ERROR),           \
        TraceLoggingString(__FUNCTION__ " returned error", "ErrorMessage"), \
        TraceLoggingLong(result, "Error"));

#define NET_EBPF_EXT_LOG_ENTRY()                                                \
    TraceLoggingWrite(                                                          \
        net_ebpf_ext_tracelog_provider,                                         \
        NET_EBPF_EXT_TRACELOG_EVENT_GENERIC_MESSAGE,                            \
        TraceLoggingLevel(WINEVENT_LEVEL_VERBOSE),                              \
        TraceLoggingKeyword(NET_EBPF_EXT_TRACELOG_KEYWORD_FUNCTION_ENTRY_EXIT), \
        TraceLoggingOpcode(WINEVENT_OPCODE_START),                              \
        TraceLoggingString(__FUNCTION__, "Enter"));

#define NET_EBPF_EXT_LOG_EXIT()                                                 \
    TraceLoggingWrite(                                                          \
        net_ebpf_ext_tracelog_provider,                                         \
        NET_EBPF_EXT_TRACELOG_EVENT_GENERIC_MESSAGE,                            \
        TraceLoggingLevel(WINEVENT_LEVEL_VERBOSE),                              \
        TraceLoggingKeyword(NET_EBPF_EXT_TRACELOG_KEYWORD_FUNCTION_ENTRY_EXIT), \
        TraceLoggingOpcode(WINEVENT_OPCODE_STOP),                               \
        TraceLoggingString(__FUNCTION__, "Exit"));

#define NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(keyword, api, status) \
    TraceLoggingWrite(                                              \
        net_ebpf_ext_tracelog_provider,                             \
        NET_EBPF_EXT_TRACELOG_EVENT_API_ERROR,                      \
        TraceLoggingLevel(WINEVENT_LEVEL_ERROR),                    \
        TraceLoggingKeyword((keyword)),                             \
        TraceLoggingString(#api, "api"),                            \
        TraceLoggingNTStatus(status));

#define NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_MESSAGE_STRING(keyword, api, status, message, value) \
    TraceLoggingWrite(                                                                             \
        net_ebpf_ext_tracelog_provider,                                                            \
        NET_EBPF_EXT_TRACELOG_EVENT_API_ERROR,                                                     \
        TraceLoggingLevel(WINEVENT_LEVEL_ERROR),                                                   \
        TraceLoggingKeyword((keyword)),                                                            \
        TraceLoggingString(#api, "api"),                                                           \
        TraceLoggingNTStatus(status),                                                              \
        TraceLoggingString(message, "Message"),                                                    \
        TraceLoggingString((value), (#value)));

#define NET_EBPF_EXT_LOG_MESSAGE(trace_level, keyword, message) \
    TraceLoggingWrite(                                          \
        net_ebpf_ext_tracelog_provider,                         \
        NET_EBPF_EXT_TRACELOG_EVENT_GENERIC_MESSAGE,            \
        TraceLoggingLevel(trace_level),                         \
        TraceLoggingKeyword((keyword)),                         \
        TraceLoggingString(message, "Message"));

#define NET_EBPF_EXT_LOG_MESSAGE_STRING(trace_level, keyword, message, value) \
    TraceLoggingWrite(                                                        \
        net_ebpf_ext_tracelog_provider,                                       \
        NET_EBPF_EXT_TRACELOG_EVENT_GENERIC_MESSAGE,                          \
        TraceLoggingLevel(trace_level),                                       \
        TraceLoggingKeyword((keyword)),                                       \
        TraceLoggingString(message, "Message"),                               \
        TraceLoggingString((value), (#value)));

#define NET_EBPF_EXT_LOG_MESSAGE_NTSTATUS(trace_level, keyword, message, status) \
    TraceLoggingWrite(                                                           \
        net_ebpf_ext_tracelog_provider,                                          \
        NET_EBPF_EXT_TRACELOG_EVENT_GENERIC_MESSAGE,                             \
        TraceLoggingLevel(trace_level),                                          \
        TraceLoggingKeyword((keyword)),                                          \
        TraceLoggingString(message, "Message"),                                  \
        TraceLoggingNTStatus(status));

#define NET_EBPF_EXT_LOG_MESSAGE_UINT32(trace_level, keyword, message, value) \
    TraceLoggingWrite(                                                        \
        net_ebpf_ext_tracelog_provider,                                       \
        NET_EBPF_EXT_TRACELOG_EVENT_GENERIC_MESSAGE,                          \
        TraceLoggingLevel(trace_level),                                       \
        TraceLoggingKeyword((keyword)),                                       \
        TraceLoggingString(message, "Message"),                               \
        TraceLoggingUInt32((value), (#value)));

#define NET_EBPF_EXT_LOG_MESSAGE_UINT64(trace_level, keyword, message, value) \
    TraceLoggingWrite(                                                        \
        net_ebpf_ext_tracelog_provider,                                       \
        NET_EBPF_EXT_TRACELOG_EVENT_GENERIC_MESSAGE,                          \
        TraceLoggingLevel(trace_level),                                       \
        TraceLoggingKeyword((keyword)),                                       \
        TraceLoggingString(message, "Message"),                               \
        TraceLoggingUInt64((value), (#value)));

#define NET_EBPF_EXT_RETURN_RESULT(status)                 \
    do {                                                   \
        ebpf_result_t local_result = (status);             \
        if (local_result == EBPF_SUCCESS) {                \
            NET_EBPF_EXT_LOG_FUNCTION_SUCCESS();           \
        } else {                                           \
            NET_EBPF_EXT_LOG_FUNCTION_ERROR(local_result); \
        }                                                  \
        return local_result;                               \
    } while (false);

#define NET_EBPF_EXT_RETURN_NTSTATUS(status)               \
    do {                                                   \
        NTSTATUS local_result = (status);                  \
        if (NT_SUCCESS(status)) {                          \
            NET_EBPF_EXT_LOG_FUNCTION_SUCCESS();           \
        } else {                                           \
            NET_EBPF_EXT_LOG_FUNCTION_ERROR(local_result); \
        }                                                  \
        return local_result;                               \
    } while (false);

#define NET_EBPF_EXT_RETURN_POINTER(type, pointer)                   \
    do {                                                             \
        type local_result = (type)(pointer);                         \
        TraceLoggingWrite(                                           \
            net_ebpf_ext_tracelog_provider,                          \
            NET_EBPF_EXT_TRACELOG_EVENT_RETURN,                      \
            TraceLoggingLevel(WINEVENT_LEVEL_VERBOSE),               \
            TraceLoggingKeyword(NET_EBPF_EXT_TRACELOG_KEYWORD_BASE), \
            TraceLoggingString(__FUNCTION__ " returned"),            \
            TraceLoggingPointer(local_result, #pointer));            \
        return local_result;                                         \
    } while (false);

#define NET_EBPF_EXT_RETURN_BOOL(flag)                               \
    do {                                                             \
        bool local_result = (flag);                                  \
        TraceLoggingWrite(                                           \
            net_ebpf_ext_tracelog_provider,                          \
            NET_EBPF_EXT_TRACELOG_EVENT_RETURN,                      \
            TraceLoggingLevel(WINEVENT_LEVEL_VERBOSE),               \
            TraceLoggingKeyword(NET_EBPF_EXT_TRACELOG_KEYWORD_BASE), \
            TraceLoggingString(__FUNCTION__ " returned"),            \
            TraceLoggingBool(!!local_result, #flag));                \
        return local_result;                                         \
    } while (false);

#define NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_UINT64_UINT64(keyword, api, status, value1, value2) \
    TraceLoggingWrite(                                                                            \
        net_ebpf_ext_tracelog_provider,                                                           \
        NET_EBPF_EXT_TRACELOG_EVENT_API_ERROR,                                                    \
        TraceLoggingLevel(WINEVENT_LEVEL_ERROR),                                                  \
        TraceLoggingKeyword((keyword)),                                                           \
        TraceLoggingString(#api, "api"),                                                          \
        TraceLoggingNTStatus(status),                                                             \
        TraceLoggingUInt64((value1), (#value1)),                                                  \
        TraceLoggingUInt64((value2), (#value2)));

#define NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64(trace_level, keyword, message, value1, value2) \
    TraceLoggingWrite(                                                                        \
        net_ebpf_ext_tracelog_provider,                                                       \
        NET_EBPF_EXT_TRACELOG_EVENT_GENERIC_MESSAGE,                                          \
        TraceLoggingLevel(trace_level),                                                       \
        TraceLoggingKeyword((keyword)),                                                       \
        TraceLoggingString(message, "Message"),                                               \
        TraceLoggingUInt64((value1), (#value1)),                                              \
        TraceLoggingUInt64((value2), (#value2)));

#define NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_UINT64(trace_level, keyword, message, value1, value2, value3) \
    TraceLoggingWrite(                                                                                       \
        net_ebpf_ext_tracelog_provider,                                                                      \
        NET_EBPF_EXT_TRACELOG_EVENT_GENERIC_MESSAGE,                                                         \
        TraceLoggingLevel(trace_level),                                                                      \
        TraceLoggingKeyword((keyword)),                                                                      \
        TraceLoggingString(message, "Message"),                                                              \
        TraceLoggingUInt64((value1), (#value1)),                                                             \
        TraceLoggingUInt64((value2), (#value2)),                                                             \
        TraceLoggingUInt64((value3), (#value3)));

#define NET_EBPF_EXT_LOG_SOCK_ADDR_CLASSIFY(trace_level, keyword, message, handle, protocol, redirect, verdict) \
    TraceLoggingWrite(                                                                                          \
        net_ebpf_ext_tracelog_provider,                                                                         \
        NET_EBPF_EXT_TRACELOG_EVENT_GENERIC_MESSAGE,                                                            \
        TraceLoggingLevel(trace_level),                                                                         \
        TraceLoggingKeyword((keyword)),                                                                         \
        TraceLoggingString(message, "Message"),                                                                 \
        TraceLoggingUInt64((handle), "TransportEndpointHandle"),                                                \
        TraceLoggingUInt64((protocol), "Protocol"),                                                             \
        TraceLoggingUInt64((redirect), "Redirected"),                                                           \
        TraceLoggingUInt64((verdict), "Verdict"));

#define NET_EBPF_EXT_BAIL_ON_ERROR_RESULT(result)          \
    do {                                                   \
        ebpf_result_t local_result = (result);             \
        if (local_result != EBPF_SUCCESS) {                \
            NET_EBPF_EXT_LOG_FUNCTION_ERROR(local_result); \
            goto Exit;                                     \
        }                                                  \
    } while (false);

#define NET_EBPF_EXT_BAIL_ON_ERROR_STATUS(status)          \
    do {                                                   \
        NTSTATUS local_status = (status);                  \
        if (!NT_SUCCESS(local_status)) {                   \
            NET_EBPF_EXT_LOG_FUNCTION_ERROR(local_status); \
            goto Exit;                                     \
        }                                                  \
    } while (false);

#define NET_EBPF_EXT_BAIL_ON_ALLOC_FAILURE_RESULT(ptr, ptr_name, result) \
    do {                                                                 \
        if ((ptr) == NULL) {                                             \
            NET_EBPF_EXT_LOG_MESSAGE(                                    \
                NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,                       \
                NET_EBPF_EXT_TRACELOG_KEYWORD_ERROR,                     \
                "Failed to allocate " #ptr_name " in " __FUNCTION__);    \
            (result) = EBPF_NO_MEMORY;                                   \
            goto Exit;                                                   \
        }                                                                \
    } while (false);

#define NET_EBPF_EXT_BAIL_ON_ALLOC_FAILURE_STATUS(ptr, ptr_name, result) \
    do {                                                                 \
        if ((ptr) == NULL) {                                             \
            NET_EBPF_EXT_LOG_MESSAGE(                                    \
                NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,                       \
                NET_EBPF_EXT_TRACELOG_KEYWORD_ERROR,                     \
                "Failed to allocate " #ptr_name " in " __FUNCTION__);    \
            (result) = STATUS_INSUFFICIENT_RESOURCES;                    \
            goto Exit;                                                   \
        }                                                                \
    } while (false);

#define NET_EBPF_EXT_BAIL_ON_API_FAILURE_STATUS(api, status)                                             \
    do {                                                                                                 \
        NTSTATUS local_status = (status);                                                                \
        if (!NT_SUCCESS(local_status)) {                                                                 \
            NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(NET_EBPF_EXT_TRACELOG_KEYWORD_ERROR, (api), (status)); \
            goto Exit;                                                                                   \
        }                                                                                                \
    } while (false);