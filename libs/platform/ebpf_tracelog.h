// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_platform.h"

TRACELOGGING_DECLARE_PROVIDER(ebpf_tracelog_provider);

#ifdef __cplusplus
extern "C"
{
#endif

#define EBPF_TRACELOG_EVENT_SUCCESS "EbpfSuccess"
#define EBPF_TRACELOG_EVENT_RETURN "EbpfReturn"
#define EBPF_TRACELOG_EVENT_GENERIC_ERROR "EbpfGenericError"
#define EBPF_TRACELOG_EVENT_GENERIC_MESSAGE "EbpfGenericMessage"
#define EBPF_TRACELOG_EVENT_API_ERROR "EbpfApiError"

#define EBPF_TRACELOG_KEYWORD_FUNCTION_ENTRY_EXIT 0x1
#define EBPF_TRACELOG_KEYWORD_BASE 0x2
#define EBPF_TRACELOG_KEYWORD_ERROR 0x4
#define EBPF_TRACELOG_KEYWORD_EPOCH 0x8
#define EBPF_TRACELOG_KEYWORD_CORE 0x10
#define EBPF_TRACELOG_KEYWORD_LINK 0x20
#define EBPF_TRACELOG_KEYWORD_MAP 0x40
#define EBPF_TRACELOG_KEYWORD_PROGRAM 0x80
#define EBPF_TRACELOG_KEYWORD_API 0x100
#define EBPF_TRACELOG_KEYWORD_PRINTK 0x200
#define EBPF_TRACELOG_KEYWORD_NATIVE 0x400

#define EBPF_TRACELOG_LEVEL_LOG_ALWAYS WINEVENT_LEVEL_LOG_ALWAYS
#define EBPF_TRACELOG_LEVEL_CRITICAL WINEVENT_LEVEL_CRITICAL
#define EBPF_TRACELOG_LEVEL_ERROR WINEVENT_LEVEL_ERROR
#define EBPF_TRACELOG_LEVEL_WARNING WINEVENT_LEVEL_WARNING
#define EBPF_TRACELOG_LEVEL_INFO WINEVENT_LEVEL_INFO
#define EBPF_TRACELOG_LEVEL_VERBOSE WINEVENT_LEVEL_VERBOSE

    typedef enum _ebpf_tracelog_keyword
    {
        _EBPF_TRACELOG_KEYWORD_FUNCTION_ENTRY_EXIT,
        _EBPF_TRACELOG_KEYWORD_BASE,
        _EBPF_TRACELOG_KEYWORD_ERROR,
        _EBPF_TRACELOG_KEYWORD_EPOCH,
        _EBPF_TRACELOG_KEYWORD_CORE,
        _EBPF_TRACELOG_KEYWORD_LINK,
        _EBPF_TRACELOG_KEYWORD_MAP,
        _EBPF_TRACELOG_KEYWORD_PROGRAM,
        _EBPF_TRACELOG_KEYWORD_API,
        _EBPF_TRACELOG_KEYWORD_PRINTK,
        _EBPF_TRACELOG_KEYWORD_NATIVE
    } ebpf_tracelog_keyword_t;

    typedef enum _ebpf_tracelog_level
    {
        _EBPF_TRACELOG_LEVEL_LOG_ALWAYS,
        _EBPF_TRACELOG_LEVEL_CRITICAL,
        _EBPF_TRACELOG_LEVEL_ERROR,
        _EBPF_TRACELOG_LEVEL_WARNING,
        _EBPF_TRACELOG_LEVEL_INFO,
        _EBPF_TRACELOG_LEVEL_VERBOSE
    } ebpf_tracelog_level_t;

    _Must_inspect_result_ ebpf_result_t
    ebpf_trace_initiate();

    void
    ebpf_trace_terminate();

#define EBPF_LOG_FUNCTION_SUCCESS()                                                             \
    if (TraceLoggingProviderEnabled(                                                            \
            ebpf_tracelog_provider, EBPF_TRACELOG_LEVEL_VERBOSE, EBPF_TRACELOG_KEYWORD_BASE)) { \
        TraceLoggingWrite(                                                                      \
            ebpf_tracelog_provider,                                                             \
            EBPF_TRACELOG_EVENT_SUCCESS,                                                        \
            TraceLoggingLevel(WINEVENT_LEVEL_VERBOSE),                                          \
            TraceLoggingKeyword(EBPF_TRACELOG_KEYWORD_BASE),                                    \
            TraceLoggingString(__FUNCTION__ " returned success", "Message"));                   \
    }

#define EBPF_LOG_FUNCTION_ERROR(result)                                                         \
    if (TraceLoggingProviderEnabled(                                                            \
            ebpf_tracelog_provider, EBPF_TRACELOG_LEVEL_VERBOSE, EBPF_TRACELOG_KEYWORD_BASE)) { \
        TraceLoggingWrite(                                                                      \
            ebpf_tracelog_provider,                                                             \
            EBPF_TRACELOG_EVENT_GENERIC_ERROR,                                                  \
            TraceLoggingLevel(WINEVENT_LEVEL_ERROR),                                            \
            TraceLoggingKeyword(EBPF_TRACELOG_KEYWORD_BASE),                                    \
            TraceLoggingString(__FUNCTION__ " returned error", "ErrorMessage"),                 \
            TraceLoggingLong(result, "Error"));                                                 \
    }

#define EBPF_LOG_ENTRY()                                                                                       \
    if (TraceLoggingProviderEnabled(                                                                           \
            ebpf_tracelog_provider, EBPF_TRACELOG_LEVEL_VERBOSE, EBPF_TRACELOG_KEYWORD_FUNCTION_ENTRY_EXIT)) { \
        TraceLoggingWrite(                                                                                     \
            ebpf_tracelog_provider,                                                                            \
            EBPF_TRACELOG_EVENT_GENERIC_MESSAGE,                                                               \
            TraceLoggingLevel(WINEVENT_LEVEL_VERBOSE),                                                         \
            TraceLoggingKeyword(EBPF_TRACELOG_KEYWORD_FUNCTION_ENTRY_EXIT),                                    \
            TraceLoggingOpcode(WINEVENT_OPCODE_START),                                                         \
            TraceLoggingString(__FUNCTION__, "Entry"));                                                        \
    }

#define EBPF_LOG_EXIT()                                                                                        \
    if (TraceLoggingProviderEnabled(                                                                           \
            ebpf_tracelog_provider, EBPF_TRACELOG_LEVEL_VERBOSE, EBPF_TRACELOG_KEYWORD_FUNCTION_ENTRY_EXIT)) { \
        TraceLoggingWrite(                                                                                     \
            ebpf_tracelog_provider,                                                                            \
            EBPF_TRACELOG_EVENT_GENERIC_MESSAGE,                                                               \
            TraceLoggingLevel(WINEVENT_LEVEL_VERBOSE),                                                         \
            TraceLoggingKeyword(EBPF_TRACELOG_KEYWORD_FUNCTION_ENTRY_EXIT),                                    \
            TraceLoggingOpcode(WINEVENT_OPCODE_STOP),                                                          \
            TraceLoggingString(__FUNCTION__, "Exit"));                                                         \
    }

#define EBPF_RETURN_ERROR(error)                   \
    do {                                           \
        uint32_t local_result = (error);           \
        if (local_result == ERROR_SUCCESS) {       \
            EBPF_LOG_FUNCTION_SUCCESS();           \
        } else {                                   \
            EBPF_LOG_FUNCTION_ERROR(local_result); \
        }                                          \
        return local_result;                       \
    } while (false);

    void
    ebpf_log_ntstatus_api_failure(ebpf_tracelog_keyword_t keyword, _In_z_ const char* api_name, NTSTATUS status);
#define EBPF_LOG_NTSTATUS_API_FAILURE(keyword, api, status)                \
    if (TraceLoggingProviderEnabled(ebpf_tracelog_provider, 0, keyword)) { \
        ebpf_log_ntstatus_api_failure(_##keyword##, #api, status);         \
    }

    void
    ebpf_log_ntstatus_api_failure_message(
        ebpf_tracelog_keyword_t keyword, _In_z_ const char* api_name, NTSTATUS status, _In_z_ const char* message);
#define EBPF_LOG_NTSTATUS_API_FAILURE_MESSAGE(keyword, api, status, message)        \
    if (TraceLoggingProviderEnabled(ebpf_tracelog_provider, 0, keyword)) {          \
        ebpf_log_ntstatus_api_failure_message(_##keyword##, #api, status, message); \
    }

    void
    ebpf_log_message(ebpf_tracelog_level_t trace_level, ebpf_tracelog_keyword_t keyword, _In_z_ const char* message);
#define EBPF_LOG_MESSAGE(trace_level, keyword, message)                              \
    if (TraceLoggingProviderEnabled(ebpf_tracelog_provider, trace_level, keyword)) { \
        ebpf_log_message(_##trace_level##, _##keyword##, message);                   \
    }

    void
    ebpf_log_message_string(
        ebpf_tracelog_level_t trace_level,
        ebpf_tracelog_keyword_t keyword,
        _In_z_ const char* message,
        _In_z_ const char* string_value);
#define EBPF_LOG_MESSAGE_STRING(trace_level, keyword, message, value)                \
    if (TraceLoggingProviderEnabled(ebpf_tracelog_provider, trace_level, keyword)) { \
        ebpf_log_message_string(_##trace_level##, _##keyword##, message, value);     \
    }

    void
    ebpf_log_message_utf8_string(
        ebpf_tracelog_level_t trace_level,
        ebpf_tracelog_keyword_t keyword,
        _In_z_ const char* message,
        _In_ const ebpf_utf8_string_t* string);
#define EBPF_LOG_MESSAGE_UTF8_STRING(trace_level, keyword, message, value)            \
    if (TraceLoggingProviderEnabled(ebpf_tracelog_provider, trace_level, keyword)) {  \
        ebpf_log_message_utf8_string(_##trace_level##, _##keyword##, message, value); \
    }

    void
    ebpf_log_message_ntstatus(
        ebpf_tracelog_level_t trace_level,
        ebpf_tracelog_keyword_t keyword,
        _In_z_ const char* message,
        NTSTATUS status);
#define EBPF_LOG_MESSAGE_NTSTATUS(trace_level, keyword, message, status)             \
    if (TraceLoggingProviderEnabled(ebpf_tracelog_provider, trace_level, keyword)) { \
        ebpf_log_message_ntstatus(_##trace_level##, _##keyword##, message, status);  \
    }

    void
    ebpf_log_message_uint64(
        ebpf_tracelog_level_t trace_level, ebpf_tracelog_keyword_t keyword, _In_z_ const char* message, uint64_t value);
#define EBPF_LOG_MESSAGE_UINT64(trace_level, keyword, message, value)                \
    if (TraceLoggingProviderEnabled(ebpf_tracelog_provider, trace_level, keyword)) { \
        ebpf_log_message_uint64(_##trace_level##, _##keyword##, message, value);     \
    }

    void
    ebpf_log_message_uint64_uint64(
        ebpf_tracelog_level_t trace_level,
        ebpf_tracelog_keyword_t keyword,
        _In_z_ const char* message,
        uint64_t value1,
        uint64_t value2);
#define EBPF_LOG_MESSAGE_UINT64_UINT64(trace_level, keyword, message, value1, value2)            \
    if (TraceLoggingProviderEnabled(ebpf_tracelog_provider, trace_level, keyword)) {             \
        ebpf_log_message_uint64_uint64(_##trace_level##, _##keyword##, message, value1, value2); \
    }

    void
    ebpf_log_message_error(
        ebpf_tracelog_level_t trace_level,
        ebpf_tracelog_keyword_t keyword,
        _In_z_ const char* message,
        ebpf_result_t error);
#define EBPF_LOG_MESSAGE_ERROR(trace_level, keyword, message, error)                 \
    if (TraceLoggingProviderEnabled(ebpf_tracelog_provider, trace_level, keyword)) { \
        ebpf_log_message_error(_##trace_level##, _##keyword##, message, error);      \
    }

    void
    ebpf_log_message_wstring(
        ebpf_tracelog_level_t trace_level,
        ebpf_tracelog_keyword_t keyword,
        _In_z_ const char* message,
        _In_z_ const wchar_t* wstring);
#define EBPF_LOG_MESSAGE_WSTRING(trace_level, keyword, message, wstring)             \
    if (TraceLoggingProviderEnabled(ebpf_tracelog_provider, trace_level, keyword)) { \
        ebpf_log_message_wstring(_##trace_level##, _##keyword##, message, wstring);  \
    }

    void
    ebpf_log_message_guid_guid_string(
        ebpf_tracelog_level_t trace_level,
        ebpf_tracelog_keyword_t keyword,
        _In_z_ const char* message,
        _In_z_ const char* string,
        _In_ const GUID* guid1,
        _In_ const GUID* guid2);
#define EBPF_LOG_MESSAGE_GUID_GUID_STRING(trace_level, keyword, message, string, guid1, guid2)            \
    if (TraceLoggingProviderEnabled(ebpf_tracelog_provider, trace_level, keyword)) {                      \
        ebpf_log_message_guid_guid_string(_##trace_level##, _##keyword##, message, string, guid1, guid2); \
    }

    void
    ebpf_log_message_guid_guid(
        ebpf_tracelog_level_t trace_level,
        ebpf_tracelog_keyword_t keyword,
        _In_z_ const char* message,
        _In_ const GUID* guid1,
        _In_ const GUID* guid2);
#define EBPF_LOG_MESSAGE_GUID_GUID(trace_level, keyword, message, guid1, guid2)            \
    if (TraceLoggingProviderEnabled(ebpf_tracelog_provider, trace_level, keyword)) {       \
        ebpf_log_message_guid_guid(_##trace_level##, _##keyword##, message, guid1, guid2); \
    }

    void
    ebpf_log_message_guid(
        ebpf_tracelog_level_t trace_level,
        ebpf_tracelog_keyword_t keyword,
        _In_z_ const char* message,
        _In_ const GUID* guid);
#define EBPF_LOG_MESSAGE_GUID(trace_level, keyword, message, guid)                   \
    if (TraceLoggingProviderEnabled(ebpf_tracelog_provider, trace_level, keyword)) { \
        ebpf_log_message_guid(_##trace_level##, _##keyword##, message, guid);        \
    }

    void
    ebpf_log_ntstatus_wstring_api(
        ebpf_tracelog_keyword_t keyword, _In_z_ const wchar_t* wstring, _In_z_ const char* api, NTSTATUS status);
#define EBPF_LOG_NTSTATUS_WSTRING_API(keyword, wstring, api, status)        \
    if (TraceLoggingProviderEnabled(ebpf_tracelog_provider, 0, keyword)) {  \
        ebpf_log_ntstatus_wstring_api(_##keyword##, wstring, #api, status); \
    }

    /////////////////////////////////////////////////////////
    // Macros built on top of the above primary trace macros.
    /////////////////////////////////////////////////////////

#define EBPF_RETURN_VOID() \
    do {                   \
        EBPF_LOG_EXIT();   \
        return;            \
    } while (false);

#define EBPF_RETURN_RESULT(status)                 \
    do {                                           \
        ebpf_result_t local_result = (status);     \
        if (local_result == EBPF_SUCCESS) {        \
            EBPF_LOG_FUNCTION_SUCCESS();           \
        } else {                                   \
            EBPF_LOG_FUNCTION_ERROR(local_result); \
        }                                          \
        return local_result;                       \
    } while (false);

#define EBPF_RETURN_NTSTATUS(status)               \
    do {                                           \
        NTSTATUS local_status = (status);          \
        if (NT_SUCCESS(local_status)) {            \
            EBPF_LOG_FUNCTION_SUCCESS();           \
        } else {                                   \
            EBPF_LOG_FUNCTION_ERROR(local_status); \
        }                                          \
        return local_status;                       \
    } while (false);

#define EBPF_RETURN_POINTER(type, pointer)                   \
    do {                                                     \
        type local_result = (type)(pointer);                 \
        TraceLoggingWrite(                                   \
            ebpf_tracelog_provider,                          \
            EBPF_TRACELOG_EVENT_RETURN,                      \
            TraceLoggingLevel(WINEVENT_LEVEL_VERBOSE),       \
            TraceLoggingKeyword(EBPF_TRACELOG_KEYWORD_BASE), \
            TraceLoggingString(__FUNCTION__ " returned"),    \
            TraceLoggingPointer(local_result, #pointer));    \
        return local_result;                                 \
    } while (false);

#define EBPF_RETURN_BOOL(flag)                               \
    do {                                                     \
        bool local_result = (flag);                          \
        TraceLoggingWrite(                                   \
            ebpf_tracelog_provider,                          \
            EBPF_TRACELOG_EVENT_RETURN,                      \
            TraceLoggingLevel(WINEVENT_LEVEL_VERBOSE),       \
            TraceLoggingKeyword(EBPF_TRACELOG_KEYWORD_BASE), \
            TraceLoggingString(__FUNCTION__ " returned"),    \
            TraceLoggingBool(!!local_result, #flag));        \
        return local_result;                                 \
    } while (false);

#define EBPF_RETURN_FD(fd)                                   \
    do {                                                     \
        fd_t local_fd = (fd);                                \
        TraceLoggingWrite(                                   \
            ebpf_tracelog_provider,                          \
            EBPF_TRACELOG_EVENT_RETURN,                      \
            TraceLoggingLevel(WINEVENT_LEVEL_VERBOSE),       \
            TraceLoggingKeyword(EBPF_TRACELOG_KEYWORD_BASE), \
            TraceLoggingString(__FUNCTION__ " returned"),    \
            TraceLoggingInt32(local_fd, #fd));               \
        return local_fd;                                     \
    } while (false)

#define EBPF_LOG_WIN32_STRING_API_FAILURE(keyword, message, api) \
    do {                                                         \
        unsigned long last_error = GetLastError();               \
        TraceLoggingWrite(                                       \
            ebpf_tracelog_provider,                              \
            EBPF_TRACELOG_EVENT_API_ERROR,                       \
            TraceLoggingLevel(EBPF_TRACELOG_LEVEL_ERROR),        \
            TraceLoggingKeyword((keyword)),                      \
            TraceLoggingString(message, "Message"),              \
            TraceLoggingString(#api, "Api"),                     \
            TraceLoggingWinError(last_error));                   \
    } while (false);

#define EBPF_LOG_WIN32_WSTRING_API_FAILURE(keyword, wstring, api) \
    do {                                                          \
        unsigned long last_error = GetLastError();                \
        TraceLoggingWrite(                                        \
            ebpf_tracelog_provider,                               \
            EBPF_TRACELOG_EVENT_API_ERROR,                        \
            TraceLoggingLevel(EBPF_TRACELOG_LEVEL_ERROR),         \
            TraceLoggingKeyword((keyword)),                       \
            TraceLoggingWideString(wstring, "Message"),           \
            TraceLoggingString(#api, "Api"),                      \
            TraceLoggingWinError(last_error));                    \
    } while (false);

//
#define EBPF_LOG_WIN32_GUID_API_FAILURE(keyword, guid, api) \
    do {                                                    \
        unsigned long last_error = GetLastError();          \
        TraceLoggingWrite(                                  \
            ebpf_tracelog_provider,                         \
            EBPF_TRACELOG_EVENT_API_ERROR,                  \
            TraceLoggingLevel(EBPF_TRACELOG_LEVEL_ERROR),   \
            TraceLoggingKeyword((keyword)),                 \
            TraceLoggingGuid((*guid), (#guid)),             \
            TraceLoggingString(#api, "Api"),                \
            TraceLoggingWinError(last_error));              \
    } while (false);

#define EBPF_LOG_WIN32_API_FAILURE(keyword, api)          \
    do {                                                  \
        unsigned long last_error = GetLastError();        \
        TraceLoggingWrite(                                \
            ebpf_tracelog_provider,                       \
            EBPF_TRACELOG_EVENT_API_ERROR,                \
            TraceLoggingLevel(EBPF_TRACELOG_LEVEL_ERROR), \
            TraceLoggingKeyword((keyword)),               \
            TraceLoggingString(#api, "Api"),              \
            TraceLoggingWinError(last_error));            \
    } while (false);

#define EBPF_LOG_MESSAGE_POINTER_ENUM(trace_level, keyword, message, pointer, enum) \
    TraceLoggingWrite(                                                              \
        ebpf_tracelog_provider,                                                     \
        EBPF_TRACELOG_EVENT_GENERIC_MESSAGE,                                        \
        TraceLoggingLevel((trace_level)),                                           \
        TraceLoggingKeyword((keyword)),                                             \
        TraceLoggingString((message), "Message"),                                   \
        TraceLoggingPointer(pointer, #pointer),                                     \
        TraceLoggingUInt32((enum), (#enum)));

#ifdef __cplusplus
}
#endif