// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

TRACELOGGING_DECLARE_PROVIDER(net_ebpf_ext_tracelog_provider);

NTSTATUS
net_ebpf_ext_trace_initiate();

void
net_ebpf_ext_trace_terminate();

#define NET_EBPF_EXT_TRACELOG_EVENT_SUCCESS "NetEbpfExtSuccess"
#define NET_EBPF_EXT_TRACELOG_EVENT_GENERIC_ERROR "NetEbpfExtGenericError"
#define NET_EBPF_EXT_TRACELOG_EVENT_GENERIC_MESSAGE "NetEbpfExtGenericMessage"
#define NET_EBPF_EXT_TRACELOG_EVENT_API_ERROR "NetEbpfExtApiError"

#define NET_EBPF_EXT_TRACELOG_KEYWORD_FUNCTION_ENTRY_EXIT 0x1
#define NET_EBPF_EXT_TRACELOG_KEYWORD_BASE 0x2
#define NET_EBPF_EXT_TRACELOG_KEYWORD_ERROR 0x4
#define NET_EBPF_EXT_TRACELOG_KEYWORD_EPOCH 0x8
#define NET_EBPF_EXT_TRACELOG_KEYWORD_CORE 0x10
#define NET_EBPF_EXT_TRACELOG_KEYWORD_XDP 0x20
#define NET_EBPF_EXT_TRACELOG_KEYWORD_BIND 0x40
#define NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR 0x80
#define NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_OPS 0x100

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
        TraceLoggingString(__FUNCTION__, "<=="));

#define NET_EBPF_EXT_LOG_EXIT()                                                 \
    TraceLoggingWrite(                                                          \
        net_ebpf_ext_tracelog_provider,                                         \
        NET_EBPF_EXT_TRACELOG_EVENT_GENERIC_MESSAGE,                            \
        TraceLoggingLevel(WINEVENT_LEVEL_VERBOSE),                              \
        TraceLoggingKeyword(NET_EBPF_EXT_TRACELOG_KEYWORD_FUNCTION_ENTRY_EXIT), \
        TraceLoggingOpcode(WINEVENT_OPCODE_STOP),                               \
        TraceLoggingString(__FUNCTION__, "==>"));

#define NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(keyword, api, status) \
    TraceLoggingWrite(                                              \
        net_ebpf_ext_tracelog_provider,                             \
        NET_EBPF_EXT_TRACELOG_EVENT_API_ERROR,                      \
        TraceLoggingLevel(EBPF_TRACELOG_LEVEL_ERROR),               \
        TraceLoggingKeyword((keyword)),                             \
        TraceLoggingString(#api, "api"),                            \
        TraceLoggingNTStatus(status));

#define NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_MESSAGE_STRING(keyword, api, status, message, value) \
    TraceLoggingWrite(                                                                             \
        net_ebpf_ext_tracelog_provider,                                                            \
        NET_EBPF_EXT_TRACELOG_EVENT_API_ERROR,                                                     \
        TraceLoggingLevel(EBPF_TRACELOG_LEVEL_ERROR),                                              \
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
