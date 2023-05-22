// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#include "ebpf_platform.h"

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
#define NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION 0x4
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

typedef enum _net_ebpf_ext_tracelog_keyword
{
    _NET_EBPF_EXT_TRACELOG_KEYWORD_BASE,
    _NET_EBPF_EXT_TRACELOG_KEYWORD_BIND,
    _NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION,
    _NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
    _NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_OPS,
    _NET_EBPF_EXT_TRACELOG_KEYWORD_XDP
} net_ebpf_ext_tracelog_keyword_t;

typedef enum _net_ebpf_ext_tracelog_level
{
    _NET_EBPF_EXT_TRACELOG_LEVEL_LOG_ALWAYS,
    _NET_EBPF_EXT_TRACELOG_LEVEL_CRITICAL,
    _NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
    _NET_EBPF_EXT_TRACELOG_LEVEL_WARNING,
    _NET_EBPF_EXT_TRACELOG_LEVEL_INFO,
    _NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE
} net_ebpf_ext_tracelog_level_t;

#define NET_EBPF_EXT_LOG_FUNCTION_SUCCESS()                                   \
    if (TraceLoggingProviderEnabled(                                          \
            net_ebpf_ext_tracelog_provider,                                   \
            NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,                              \
            NET_EBPF_EXT_TRACELOG_KEYWORD_BASE)) {                            \
        TraceLoggingWrite(                                                    \
            net_ebpf_ext_tracelog_provider,                                   \
            NET_EBPF_EXT_TRACELOG_EVENT_SUCCESS,                              \
            TraceLoggingLevel(WINEVENT_LEVEL_VERBOSE),                        \
            TraceLoggingKeyword(NET_EBPF_EXT_TRACELOG_KEYWORD_BASE),          \
            TraceLoggingString(__FUNCTION__ " returned success", "Message")); \
    }

#define NET_EBPF_EXT_LOG_FUNCTION_ERROR(result)                                 \
    if (TraceLoggingProviderEnabled(                                            \
            net_ebpf_ext_tracelog_provider,                                     \
            NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,                                \
            NET_EBPF_EXT_TRACELOG_KEYWORD_BASE)) {                              \
        TraceLoggingWrite(                                                      \
            net_ebpf_ext_tracelog_provider,                                     \
            NET_EBPF_EXT_TRACELOG_EVENT_GENERIC_ERROR,                          \
            TraceLoggingLevel(WINEVENT_LEVEL_ERROR),                            \
            TraceLoggingKeyword(NET_EBPF_EXT_TRACELOG_KEYWORD_BASE),            \
            TraceLoggingString(__FUNCTION__ " returned error", "ErrorMessage"), \
            TraceLoggingLong(result, "Error"));                                 \
    }

#define NET_EBPF_EXT_LOG_ENTRY()                                                    \
    if (TraceLoggingProviderEnabled(                                                \
            net_ebpf_ext_tracelog_provider,                                         \
            NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,                                    \
            NET_EBPF_EXT_TRACELOG_KEYWORD_FUNCTION_ENTRY_EXIT)) {                   \
        TraceLoggingWrite(                                                          \
            net_ebpf_ext_tracelog_provider,                                         \
            NET_EBPF_EXT_TRACELOG_EVENT_GENERIC_MESSAGE,                            \
            TraceLoggingLevel(WINEVENT_LEVEL_VERBOSE),                              \
            TraceLoggingKeyword(NET_EBPF_EXT_TRACELOG_KEYWORD_FUNCTION_ENTRY_EXIT), \
            TraceLoggingOpcode(WINEVENT_OPCODE_START),                              \
            TraceLoggingString(__FUNCTION__, "Enter"));                             \
    }

#define NET_EBPF_EXT_LOG_EXIT()                                                     \
    if (TraceLoggingProviderEnabled(                                                \
            net_ebpf_ext_tracelog_provider,                                         \
            NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,                                    \
            NET_EBPF_EXT_TRACELOG_KEYWORD_FUNCTION_ENTRY_EXIT)) {                   \
        TraceLoggingWrite(                                                          \
            net_ebpf_ext_tracelog_provider,                                         \
            NET_EBPF_EXT_TRACELOG_EVENT_GENERIC_MESSAGE,                            \
            TraceLoggingLevel(WINEVENT_LEVEL_VERBOSE),                              \
            TraceLoggingKeyword(NET_EBPF_EXT_TRACELOG_KEYWORD_FUNCTION_ENTRY_EXIT), \
            TraceLoggingOpcode(WINEVENT_OPCODE_STOP),                               \
            TraceLoggingString(__FUNCTION__, "Exit"));                              \
    }

#define _NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(keyword, api, status) \
    TraceLoggingWrite(                                               \
        net_ebpf_ext_tracelog_provider,                              \
        NET_EBPF_EXT_TRACELOG_EVENT_API_ERROR,                       \
        TraceLoggingLevel(WINEVENT_LEVEL_ERROR),                     \
        TraceLoggingKeyword((keyword)),                              \
        TraceLoggingString(api, "api"),                              \
        TraceLoggingNTStatus(status));
void
net_ebpf_ext_log_ntstatus_api_failure(
    net_ebpf_ext_tracelog_keyword_t keyword, _In_z_ const char* api_name, NTSTATUS status);
#define NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(keyword, api, status)                \
    if (TraceLoggingProviderEnabled(net_ebpf_ext_tracelog_provider, 0, keyword)) { \
        net_ebpf_ext_log_ntstatus_api_failure(_##keyword##, api, status);          \
    }

#define _NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_MESSAGE_STRING(keyword, api, status, message, value) \
    TraceLoggingWrite(                                                                              \
        net_ebpf_ext_tracelog_provider,                                                             \
        NET_EBPF_EXT_TRACELOG_EVENT_API_ERROR,                                                      \
        TraceLoggingLevel(WINEVENT_LEVEL_ERROR),                                                    \
        TraceLoggingKeyword((keyword)),                                                             \
        TraceLoggingString(api, "api"),                                                             \
        TraceLoggingNTStatus(status),                                                               \
        TraceLoggingString(message, "Message"),                                                     \
        TraceLoggingString((value), (#value)));
void
net_ebpf_ext_log_ntstatus_api_failure_message_string(
    net_ebpf_ext_tracelog_keyword_t keyword,
    _In_z_ const char* api_name,
    NTSTATUS status,
    _In_z_ const char* message,
    _In_z_ const char* string_value);
#define NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_MESSAGE_STRING(keyword, api, status, message, string_value)       \
    if (TraceLoggingProviderEnabled(net_ebpf_ext_tracelog_provider, 0, keyword)) {                              \
        net_ebpf_ext_log_ntstatus_api_failure_message_string(_##keyword##, api, status, message, string_value); \
    }

#define _NET_EBPF_EXT_LOG_MESSAGE(trace_level, keyword, message) \
    TraceLoggingWrite(                                           \
        net_ebpf_ext_tracelog_provider,                          \
        NET_EBPF_EXT_TRACELOG_EVENT_GENERIC_MESSAGE,             \
        TraceLoggingLevel(trace_level),                          \
        TraceLoggingKeyword((keyword)),                          \
        TraceLoggingString(message, "Message"));
void
net_ebpf_ext_log_message(
    net_ebpf_ext_tracelog_level_t trace_level, net_ebpf_ext_tracelog_keyword_t keyword, _In_z_ const char* message);
#define NET_EBPF_EXT_LOG_MESSAGE(trace_level, keyword, message)                              \
    if (TraceLoggingProviderEnabled(net_ebpf_ext_tracelog_provider, trace_level, keyword)) { \
        net_ebpf_ext_log_message(_##trace_level##, _##keyword##, message);                   \
    }

#define _NET_EBPF_EXT_LOG_MESSAGE_STRING(trace_level, keyword, message, value) \
    TraceLoggingWrite(                                                         \
        net_ebpf_ext_tracelog_provider,                                        \
        NET_EBPF_EXT_TRACELOG_EVENT_GENERIC_MESSAGE,                           \
        TraceLoggingLevel(trace_level),                                        \
        TraceLoggingKeyword((keyword)),                                        \
        TraceLoggingString(message, "Message"),                                \
        TraceLoggingString((value), (#value)));
void
net_ebpf_ext_log_message_string(
    net_ebpf_ext_tracelog_level_t trace_level,
    net_ebpf_ext_tracelog_keyword_t keyword,
    _In_z_ const char* message,
    _In_z_ const char* string_value);
#define NET_EBPF_EXT_LOG_MESSAGE_STRING(trace_level, keyword, message, value)                \
    if (TraceLoggingProviderEnabled(net_ebpf_ext_tracelog_provider, trace_level, keyword)) { \
        net_ebpf_ext_log_message_string(_##trace_level##, _##keyword##, message, value);     \
    }

#define _NET_EBPF_EXT_LOG_MESSAGE_NTSTATUS(trace_level, keyword, message, status) \
    TraceLoggingWrite(                                                            \
        net_ebpf_ext_tracelog_provider,                                           \
        NET_EBPF_EXT_TRACELOG_EVENT_GENERIC_MESSAGE,                              \
        TraceLoggingLevel(trace_level),                                           \
        TraceLoggingKeyword((keyword)),                                           \
        TraceLoggingString(message, "Message"),                                   \
        TraceLoggingNTStatus(status));
void
net_ebpf_ext_log_message_ntstatus(
    net_ebpf_ext_tracelog_level_t trace_level,
    net_ebpf_ext_tracelog_keyword_t keyword,
    _In_z_ const char* message,
    NTSTATUS status);
#define NET_EBPF_EXT_LOG_MESSAGE_NTSTATUS(trace_level, keyword, message, status)             \
    if (TraceLoggingProviderEnabled(net_ebpf_ext_tracelog_provider, trace_level, keyword)) { \
        net_ebpf_ext_log_message_ntstatus(_##trace_level##, _##keyword##, message, status);  \
    }

#define _NET_EBPF_EXT_LOG_MESSAGE_UINT32(trace_level, keyword, message, value) \
    TraceLoggingWrite(                                                         \
        net_ebpf_ext_tracelog_provider,                                        \
        NET_EBPF_EXT_TRACELOG_EVENT_GENERIC_MESSAGE,                           \
        TraceLoggingLevel(trace_level),                                        \
        TraceLoggingKeyword((keyword)),                                        \
        TraceLoggingString(message, "Message"),                                \
        TraceLoggingUInt32((value), (#value)));
void
net_ebpf_ext_log_message_uint32(
    net_ebpf_ext_tracelog_level_t trace_level,
    net_ebpf_ext_tracelog_keyword_t keyword,
    _In_z_ const char* message,
    uint32_t value);
#define NET_EBPF_EXT_LOG_MESSAGE_UINT32(trace_level, keyword, message, value)                \
    if (TraceLoggingProviderEnabled(net_ebpf_ext_tracelog_provider, trace_level, keyword)) { \
        net_ebpf_ext_log_message_uint32(_##trace_level##, _##keyword##, message, value);     \
    }

#define _NET_EBPF_EXT_LOG_MESSAGE_UINT64(trace_level, keyword, message, value) \
    TraceLoggingWrite(                                                         \
        net_ebpf_ext_tracelog_provider,                                        \
        NET_EBPF_EXT_TRACELOG_EVENT_GENERIC_MESSAGE,                           \
        TraceLoggingLevel(trace_level),                                        \
        TraceLoggingKeyword((keyword)),                                        \
        TraceLoggingString(message, "Message"),                                \
        TraceLoggingUInt64((value), (#value)));
void
net_ebpf_ext_log_message_uint64(
    net_ebpf_ext_tracelog_level_t trace_level,
    net_ebpf_ext_tracelog_keyword_t keyword,
    _In_z_ const char* message,
    uint64_t value);
#define NET_EBPF_EXT_LOG_MESSAGE_UINT64(trace_level, keyword, message, value)                \
    if (TraceLoggingProviderEnabled(net_ebpf_ext_tracelog_provider, trace_level, keyword)) { \
        net_ebpf_ext_log_message_uint64(_##trace_level##, _##keyword##, message, value);     \
    }

#define _NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_UINT64_UINT64(keyword, api, status, value1, value2) \
    TraceLoggingWrite(                                                                             \
        net_ebpf_ext_tracelog_provider,                                                            \
        NET_EBPF_EXT_TRACELOG_EVENT_API_ERROR,                                                     \
        TraceLoggingLevel(WINEVENT_LEVEL_ERROR),                                                   \
        TraceLoggingKeyword(keyword),                                                              \
        TraceLoggingString(api, "api"),                                                            \
        TraceLoggingNTStatus(status),                                                              \
        TraceLoggingUInt64((value1), (#value1)),                                                   \
        TraceLoggingUInt64((value2), (#value2)));
void
net_ebpf_ext_log_ntstatus_api_failure_uint64_uint64(
    net_ebpf_ext_tracelog_keyword_t keyword, _In_z_ const char* api, NTSTATUS status, uint64_t value1, uint64_t value2);
#define NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_UINT64_UINT64(keyword, api, status, value1, value2)       \
    if (TraceLoggingProviderEnabled(net_ebpf_ext_tracelog_provider, 0, keyword)) {                      \
        net_ebpf_ext_log_ntstatus_api_failure_uint64_uint64(_##keyword##, api, status, value1, value2); \
    }

#define _NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64(trace_level, keyword, message, value1, value2) \
    TraceLoggingWrite(                                                                         \
        net_ebpf_ext_tracelog_provider,                                                        \
        NET_EBPF_EXT_TRACELOG_EVENT_GENERIC_MESSAGE,                                           \
        TraceLoggingLevel(trace_level),                                                        \
        TraceLoggingKeyword((keyword)),                                                        \
        TraceLoggingString(message, "Message"),                                                \
        TraceLoggingUInt64((value1), (#value1)),                                               \
        TraceLoggingUInt64((value2), (#value2)));
void
net_ebpf_ext_log_message_uint64_uint64(
    net_ebpf_ext_tracelog_level_t trace_level,
    net_ebpf_ext_tracelog_keyword_t keyword,
    _In_z_ const char* message,
    uint64_t value1,
    uint64_t value2);
#define NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64(trace_level, keyword, message, value1, value2)            \
    if (TraceLoggingProviderEnabled(net_ebpf_ext_tracelog_provider, trace_level, keyword)) {             \
        net_ebpf_ext_log_message_uint64_uint64(_##trace_level##, _##keyword##, message, value1, value2); \
    }

#define _NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_UINT64(trace_level, keyword, message, value1, value2, value3) \
    TraceLoggingWrite(                                                                                        \
        net_ebpf_ext_tracelog_provider,                                                                       \
        NET_EBPF_EXT_TRACELOG_EVENT_GENERIC_MESSAGE,                                                          \
        TraceLoggingLevel(trace_level),                                                                       \
        TraceLoggingKeyword((keyword)),                                                                       \
        TraceLoggingString(message, "Message"),                                                               \
        TraceLoggingUInt64((value1), (#value1)),                                                              \
        TraceLoggingUInt64((value2), (#value2)),                                                              \
        TraceLoggingUInt64((value3), (#value3)));
void
net_ebpf_ext_log_message_uint64_uint64_uint64(
    net_ebpf_ext_tracelog_level_t trace_level,
    net_ebpf_ext_tracelog_keyword_t keyword,
    _In_z_ const char* message,
    uint64_t value1,
    uint64_t value2,
    uint64_t value3);
#define NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_UINT64(trace_level, keyword, message, value1, value2, value3) \
    if (TraceLoggingProviderEnabled(net_ebpf_ext_tracelog_provider, trace_level, keyword)) {                 \
        net_ebpf_ext_log_message_uint64_uint64_uint64(                                                       \
            _##trace_level##, _##keyword##, message, value1, value2, value3);                                \
    }
//
// Macros built on top of the above primary trace macros.
//

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
        if (NT_SUCCESS(local_result)) {                    \
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

#define NET_EBPF_EXT_BAIL_ON_ALLOC_FAILURE_RESULT(keyword, ptr, ptr_name, result)                                     \
    do {                                                                                                              \
        if ((ptr) == NULL) {                                                                                          \
            NET_EBPF_EXT_LOG_MESSAGE(                                                                                 \
                NET_EBPF_EXT_TRACELOG_LEVEL_ERROR, ##keyword##, "Failed to allocate " #ptr_name " in " __FUNCTION__); \
            (result) = EBPF_NO_MEMORY;                                                                                \
            goto Exit;                                                                                                \
        }                                                                                                             \
    } while (false);

#define NET_EBPF_EXT_BAIL_ON_ALLOC_FAILURE_STATUS(keyword, ptr, ptr_name, result)                                     \
    do {                                                                                                              \
        if ((ptr) == NULL) {                                                                                          \
            NET_EBPF_EXT_LOG_MESSAGE(                                                                                 \
                NET_EBPF_EXT_TRACELOG_LEVEL_ERROR, ##keyword##, "Failed to allocate " #ptr_name " in " __FUNCTION__); \
            (result) = STATUS_INSUFFICIENT_RESOURCES;                                                                 \
            goto Exit;                                                                                                \
        }                                                                                                             \
    } while (false);

#define NET_EBPF_EXT_BAIL_ON_API_FAILURE_STATUS(keyword, api, status)            \
    do {                                                                         \
        NTSTATUS local_status = (status);                                        \
        if (!NT_SUCCESS(local_status)) {                                         \
            NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(##keyword##, (api), (status)); \
            goto Exit;                                                           \
        }                                                                        \
    } while (false);