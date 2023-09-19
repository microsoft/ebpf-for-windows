// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "net_ebpf_ext.h"

#include <TraceLoggingProvider.h>
#include <winmeta.h>

TRACELOGGING_DEFINE_PROVIDER(
    net_ebpf_ext_tracelog_provider,
    "NetEbpfExtProvider",
    // {f2f2ca01-ad02-4a07-9e90-95a2334f3692}
    (0xf2f2ca01, 0xad02, 0x4a07, 0x9e, 0x90, 0x95, 0xa2, 0x33, 0x4f, 0x36, 0x92));

static bool _net_ebpf_ext_trace_initiated = false;

NTSTATUS
net_ebpf_ext_trace_initiate()
{
    NTSTATUS status = STATUS_SUCCESS;
    if (_net_ebpf_ext_trace_initiated) {
        goto Exit;
    }

    status = TraceLoggingRegister(net_ebpf_ext_tracelog_provider);
    if (status != STATUS_SUCCESS) {
        goto Exit;
    } else {
        _net_ebpf_ext_trace_initiated = true;
    }
Exit:
    return status;
}

// Prevent tail call optimization of the call to TraceLoggingUnregister to resolve verifier stop C4/DD
// "An attempt was made to unload a driver without calling EtwUnregister".
#pragma optimize("", off)
void
net_ebpf_ext_trace_terminate()
{
    if (_net_ebpf_ext_trace_initiated) {
        TraceLoggingUnregister(net_ebpf_ext_tracelog_provider);
        _net_ebpf_ext_trace_initiated = false;
    }
}
#pragma optimize("", on)

#define KEYWORD_BASE NET_EBPF_EXT_TRACELOG_KEYWORD_BASE
#define KEYWORD_BIND NET_EBPF_EXT_TRACELOG_KEYWORD_BIND
#define KEYWORD_EXT NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION
#define KEYWORD_SOCK_ADDR NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR
#define KEYWORD_SOCK_OPS NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_OPS
#define KEYWORD_XDP NET_EBPF_EXT_TRACELOG_KEYWORD_XDP

#define CASE_BASE case _NET_EBPF_EXT_TRACELOG_KEYWORD_BASE
#define CASE_BIND case _NET_EBPF_EXT_TRACELOG_KEYWORD_BIND
#define CASE_EXT case _NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION
#define CASE_SOCK_ADDR case _NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR
#define CASE_SOCK_OPS case _NET_EBPF_EXT_TRACELOG_KEYWORD_SOCK_OPS
#define CASE_XDP case _NET_EBPF_EXT_TRACELOG_KEYWORD_XDP

#define LEVEL_LOG_ALWAYS NET_EBPF_EXT_TRACELOG_LEVEL_LOG_ALWAYS
#define LEVEL_CRITICAL NET_EBPF_EXT_TRACELOG_LEVEL_CRITICAL
#define LEVEL_ERROR NET_EBPF_EXT_TRACELOG_LEVEL_ERROR
#define LEVEL_WARNING NET_EBPF_EXT_TRACELOG_LEVEL_WARNING
#define LEVEL_INFO NET_EBPF_EXT_TRACELOG_LEVEL_INFO
#define LEVEL_VERBOSE NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE

#define CASE_LOG_ALWAYS case _NET_EBPF_EXT_TRACELOG_LEVEL_LOG_ALWAYS
#define CASE_CRITICAL case _NET_EBPF_EXT_TRACELOG_LEVEL_CRITICAL
#define CASE_LEVEL_ERROR case _NET_EBPF_EXT_TRACELOG_LEVEL_ERROR
#define CASE_WARNING case _NET_EBPF_EXT_TRACELOG_LEVEL_WARNING
#define CASE_INFO case _NET_EBPF_EXT_TRACELOG_LEVEL_INFO
#define CASE_VERBOSE case _NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE

#define NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_KEYWORD_SWITCH(api_name, status)       \
    switch (keyword) {                                                               \
    CASE_BASE:                                                                       \
        _NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(KEYWORD_BASE, api_name, status);      \
        break;                                                                       \
    CASE_EXT:                                                                        \
        _NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(KEYWORD_EXT, api_name, status);       \
        break;                                                                       \
    CASE_BIND:                                                                       \
        _NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(KEYWORD_BIND, api_name, status);      \
        break;                                                                       \
    CASE_SOCK_ADDR:                                                                  \
        _NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(KEYWORD_SOCK_ADDR, api_name, status); \
        break;                                                                       \
    CASE_SOCK_OPS:                                                                   \
        _NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(KEYWORD_SOCK_OPS, api_name, status);  \
        break;                                                                       \
    CASE_XDP:                                                                        \
        _NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(KEYWORD_XDP, api_name, status);       \
        break;                                                                       \
    default:                                                                         \
        ebpf_assert(!"Invalid keyword");                                             \
        break;                                                                       \
    }

#pragma warning(push)
#pragma warning(disable : 6262) // Function uses 'N' bytes of stack.  Consider moving some data to heap.

__declspec(noinline) void net_ebpf_ext_log_ntstatus_api_failure(
    net_ebpf_ext_tracelog_keyword_t keyword, _In_z_ const char* api_name, NTSTATUS status)
{
    NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_KEYWORD_SWITCH(api_name, status);
}

#define NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_MESSAGE_STRING_KEYWORD_SWITCH(api_name, status, message, string_value)  \
    switch (keyword) {                                                                                                \
    CASE_BASE:                                                                                                        \
        _NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_MESSAGE_STRING(KEYWORD_BASE, api_name, status, message, string_value); \
        break;                                                                                                        \
    CASE_EXT:                                                                                                         \
        _NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_MESSAGE_STRING(KEYWORD_EXT, api_name, status, message, string_value);  \
        break;                                                                                                        \
    CASE_BIND:                                                                                                        \
        _NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_MESSAGE_STRING(KEYWORD_BIND, api_name, status, message, string_value); \
        break;                                                                                                        \
    CASE_SOCK_ADDR:                                                                                                   \
        _NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_MESSAGE_STRING(                                                        \
            KEYWORD_SOCK_ADDR, api_name, status, message, string_value);                                              \
        break;                                                                                                        \
    CASE_SOCK_OPS:                                                                                                    \
        _NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_MESSAGE_STRING(                                                        \
            KEYWORD_SOCK_OPS, api_name, status, message, string_value);                                               \
        break;                                                                                                        \
    CASE_XDP:                                                                                                         \
        _NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_MESSAGE_STRING(KEYWORD_XDP, api_name, status, message, string_value);  \
        break;                                                                                                        \
    default:                                                                                                          \
        ebpf_assert(!"Invalid keyword");                                                                              \
        break;                                                                                                        \
    }

__declspec(noinline) void net_ebpf_ext_log_ntstatus_api_failure_message_string(
    net_ebpf_ext_tracelog_keyword_t keyword,
    _In_z_ const char* api_name,
    NTSTATUS status,
    _In_z_ const char* message,
    _In_z_ const char* string_value)
{
    NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_MESSAGE_STRING_KEYWORD_SWITCH(api_name, status, message, string_value);
}

#define NET_EBPF_EXT_LOG_MESSAGE_KEYWORD_SWITCH(trace_level, message)       \
    switch (keyword) {                                                      \
    CASE_BASE:                                                              \
        _NET_EBPF_EXT_LOG_MESSAGE(trace_level, KEYWORD_BASE, message);      \
        break;                                                              \
    CASE_BIND:                                                              \
        _NET_EBPF_EXT_LOG_MESSAGE(trace_level, KEYWORD_BIND, message);      \
        break;                                                              \
    CASE_EXT:                                                               \
        _NET_EBPF_EXT_LOG_MESSAGE(trace_level, KEYWORD_EXT, message);       \
        break;                                                              \
    CASE_SOCK_ADDR:                                                         \
        _NET_EBPF_EXT_LOG_MESSAGE(trace_level, KEYWORD_SOCK_ADDR, message); \
        break;                                                              \
    CASE_SOCK_OPS:                                                          \
        _NET_EBPF_EXT_LOG_MESSAGE(trace_level, KEYWORD_SOCK_OPS, message);  \
        break;                                                              \
    CASE_XDP:                                                               \
        _NET_EBPF_EXT_LOG_MESSAGE(trace_level, KEYWORD_XDP, message);       \
        break;                                                              \
    default:                                                                \
        ebpf_assert(!"Invalid keyword");                                    \
        break;                                                              \
    }

__declspec(noinline) void net_ebpf_ext_log_message(
    net_ebpf_ext_tracelog_level_t trace_level, net_ebpf_ext_tracelog_keyword_t keyword, _In_z_ const char* message)
{
    switch (trace_level) {
    CASE_LOG_ALWAYS:
        NET_EBPF_EXT_LOG_MESSAGE_KEYWORD_SWITCH(LEVEL_LOG_ALWAYS, message);
        break;
    CASE_CRITICAL:
        NET_EBPF_EXT_LOG_MESSAGE_KEYWORD_SWITCH(LEVEL_CRITICAL, message);
        break;
    CASE_LEVEL_ERROR:
        NET_EBPF_EXT_LOG_MESSAGE_KEYWORD_SWITCH(LEVEL_ERROR, message);
        break;
    CASE_WARNING:
        NET_EBPF_EXT_LOG_MESSAGE_KEYWORD_SWITCH(LEVEL_WARNING, message);
        break;
    CASE_INFO:
        NET_EBPF_EXT_LOG_MESSAGE_KEYWORD_SWITCH(LEVEL_INFO, message);
        break;
    CASE_VERBOSE:
        NET_EBPF_EXT_LOG_MESSAGE_KEYWORD_SWITCH(LEVEL_VERBOSE, message);
        break;
    default:
        ebpf_assert(!"Invalid trace level");
        break;
    }
}

#define NET_EBPF_EXT_LOG_MESSAGE_STRING_KEYWORD_SWITCH(trace_level, message, string_value)       \
    switch (keyword) {                                                                           \
    CASE_BASE:                                                                                   \
        _NET_EBPF_EXT_LOG_MESSAGE_STRING(trace_level, KEYWORD_BASE, message, string_value);      \
        break;                                                                                   \
    CASE_BIND:                                                                                   \
        _NET_EBPF_EXT_LOG_MESSAGE_STRING(trace_level, KEYWORD_BIND, message, string_value);      \
        break;                                                                                   \
    CASE_EXT:                                                                                    \
        _NET_EBPF_EXT_LOG_MESSAGE_STRING(trace_level, KEYWORD_EXT, message, string_value);       \
        break;                                                                                   \
    CASE_SOCK_ADDR:                                                                              \
        _NET_EBPF_EXT_LOG_MESSAGE_STRING(trace_level, KEYWORD_SOCK_ADDR, message, string_value); \
        break;                                                                                   \
    CASE_SOCK_OPS:                                                                               \
        _NET_EBPF_EXT_LOG_MESSAGE_STRING(trace_level, KEYWORD_SOCK_OPS, message, string_value);  \
        break;                                                                                   \
    CASE_XDP:                                                                                    \
        _NET_EBPF_EXT_LOG_MESSAGE_STRING(trace_level, KEYWORD_XDP, message, string_value);       \
        break;                                                                                   \
    default:                                                                                     \
        ebpf_assert(!"Invalid keyword");                                                         \
        break;                                                                                   \
    }

__declspec(noinline) void net_ebpf_ext_log_message_string(
    net_ebpf_ext_tracelog_level_t trace_level,
    net_ebpf_ext_tracelog_keyword_t keyword,
    _In_z_ const char* message,
    _In_z_ const char* string_value)
{
    switch (trace_level) {
    CASE_LOG_ALWAYS:
        NET_EBPF_EXT_LOG_MESSAGE_STRING_KEYWORD_SWITCH(LEVEL_LOG_ALWAYS, message, string_value);
        break;
    CASE_CRITICAL:
        NET_EBPF_EXT_LOG_MESSAGE_STRING_KEYWORD_SWITCH(LEVEL_CRITICAL, message, string_value);
        break;
    CASE_LEVEL_ERROR:
        NET_EBPF_EXT_LOG_MESSAGE_STRING_KEYWORD_SWITCH(LEVEL_ERROR, message, string_value);
        break;
    CASE_WARNING:
        NET_EBPF_EXT_LOG_MESSAGE_STRING_KEYWORD_SWITCH(LEVEL_WARNING, message, string_value);
        break;
    CASE_INFO:
        NET_EBPF_EXT_LOG_MESSAGE_STRING_KEYWORD_SWITCH(LEVEL_INFO, message, string_value);
        break;
    CASE_VERBOSE:
        NET_EBPF_EXT_LOG_MESSAGE_STRING_KEYWORD_SWITCH(LEVEL_VERBOSE, message, string_value);
        break;
    default:
        ebpf_assert(!"Invalid trace level");
        break;
    }
}

#define NET_EBPF_EXT_LOG_MESSAGE_NTSTATUS_KEYWORD_SWITCH(trace_level, message, status)       \
    switch (keyword) {                                                                       \
    CASE_BASE:                                                                               \
        _NET_EBPF_EXT_LOG_MESSAGE_NTSTATUS(trace_level, KEYWORD_BASE, message, status);      \
        break;                                                                               \
    CASE_BIND:                                                                               \
        _NET_EBPF_EXT_LOG_MESSAGE_NTSTATUS(trace_level, KEYWORD_BIND, message, status);      \
        break;                                                                               \
    CASE_EXT:                                                                                \
        _NET_EBPF_EXT_LOG_MESSAGE_NTSTATUS(trace_level, KEYWORD_EXT, message, status);       \
        break;                                                                               \
    CASE_SOCK_ADDR:                                                                          \
        _NET_EBPF_EXT_LOG_MESSAGE_NTSTATUS(trace_level, KEYWORD_SOCK_ADDR, message, status); \
        break;                                                                               \
    CASE_SOCK_OPS:                                                                           \
        _NET_EBPF_EXT_LOG_MESSAGE_NTSTATUS(trace_level, KEYWORD_SOCK_OPS, message, status);  \
        break;                                                                               \
    CASE_XDP:                                                                                \
        _NET_EBPF_EXT_LOG_MESSAGE_NTSTATUS(trace_level, KEYWORD_XDP, message, status);       \
        break;                                                                               \
    default:                                                                                 \
        ebpf_assert(!"Invalid keyword");                                                     \
        break;                                                                               \
    }

__declspec(noinline) void net_ebpf_ext_log_message_ntstatus(
    net_ebpf_ext_tracelog_level_t trace_level,
    net_ebpf_ext_tracelog_keyword_t keyword,
    _In_z_ const char* message,
    NTSTATUS status)
{
    switch (trace_level) {
    CASE_LOG_ALWAYS:
        NET_EBPF_EXT_LOG_MESSAGE_NTSTATUS_KEYWORD_SWITCH(LEVEL_LOG_ALWAYS, message, status);
        break;
    CASE_CRITICAL:
        NET_EBPF_EXT_LOG_MESSAGE_NTSTATUS_KEYWORD_SWITCH(LEVEL_CRITICAL, message, status);
        break;
    CASE_LEVEL_ERROR:
        NET_EBPF_EXT_LOG_MESSAGE_NTSTATUS_KEYWORD_SWITCH(LEVEL_ERROR, message, status);
        break;
    CASE_WARNING:
        NET_EBPF_EXT_LOG_MESSAGE_NTSTATUS_KEYWORD_SWITCH(LEVEL_WARNING, message, status);
        break;
    CASE_INFO:
        NET_EBPF_EXT_LOG_MESSAGE_NTSTATUS_KEYWORD_SWITCH(LEVEL_INFO, message, status);
        break;
    CASE_VERBOSE:
        NET_EBPF_EXT_LOG_MESSAGE_NTSTATUS_KEYWORD_SWITCH(LEVEL_VERBOSE, message, status);
        break;
    default:
        ebpf_assert(!"Invalid trace level");
        break;
    }
}

#define NET_EBPF_EXT_LOG_MESSAGE_UINT32_KEYWORD_SWITCH(trace_level, message, status)       \
    switch (keyword) {                                                                     \
    CASE_BASE:                                                                             \
        _NET_EBPF_EXT_LOG_MESSAGE_UINT32(trace_level, KEYWORD_BASE, message, status);      \
        break;                                                                             \
    CASE_BIND:                                                                             \
        _NET_EBPF_EXT_LOG_MESSAGE_UINT32(trace_level, KEYWORD_BIND, message, status);      \
        break;                                                                             \
    CASE_EXT:                                                                              \
        _NET_EBPF_EXT_LOG_MESSAGE_UINT32(trace_level, KEYWORD_EXT, message, status);       \
        break;                                                                             \
    CASE_SOCK_ADDR:                                                                        \
        _NET_EBPF_EXT_LOG_MESSAGE_UINT32(trace_level, KEYWORD_SOCK_ADDR, message, status); \
        break;                                                                             \
    CASE_SOCK_OPS:                                                                         \
        _NET_EBPF_EXT_LOG_MESSAGE_UINT32(trace_level, KEYWORD_SOCK_OPS, message, status);  \
        break;                                                                             \
    CASE_XDP:                                                                              \
        _NET_EBPF_EXT_LOG_MESSAGE_UINT32(trace_level, KEYWORD_XDP, message, status);       \
        break;                                                                             \
    default:                                                                               \
        ebpf_assert(!"Invalid keyword");                                                   \
        break;                                                                             \
    }

__declspec(noinline) void net_ebpf_ext_log_message_uint32(
    net_ebpf_ext_tracelog_level_t trace_level,
    net_ebpf_ext_tracelog_keyword_t keyword,
    _In_z_ const char* message,
    uint32_t value)
{
    switch (trace_level) {
    CASE_LOG_ALWAYS:
        NET_EBPF_EXT_LOG_MESSAGE_UINT32_KEYWORD_SWITCH(LEVEL_LOG_ALWAYS, message, value);
        break;
    CASE_CRITICAL:
        NET_EBPF_EXT_LOG_MESSAGE_UINT32_KEYWORD_SWITCH(LEVEL_CRITICAL, message, value);
        break;
    CASE_LEVEL_ERROR:
        NET_EBPF_EXT_LOG_MESSAGE_UINT32_KEYWORD_SWITCH(LEVEL_ERROR, message, value);
        break;
    CASE_WARNING:
        NET_EBPF_EXT_LOG_MESSAGE_UINT32_KEYWORD_SWITCH(LEVEL_WARNING, message, value);
        break;
    CASE_INFO:
        NET_EBPF_EXT_LOG_MESSAGE_UINT32_KEYWORD_SWITCH(LEVEL_INFO, message, value);
        break;
    CASE_VERBOSE:
        NET_EBPF_EXT_LOG_MESSAGE_UINT32_KEYWORD_SWITCH(LEVEL_VERBOSE, message, value);
        break;
    default:
        ebpf_assert(!"Invalid trace level");
        break;
    }
}

#define NET_EBPF_EXT_LOG_MESSAGE_UINT64_KEYWORD_SWITCH(trace_level, message, status)       \
    switch (keyword) {                                                                     \
    CASE_BASE:                                                                             \
        _NET_EBPF_EXT_LOG_MESSAGE_UINT64(trace_level, KEYWORD_BASE, message, status);      \
        break;                                                                             \
    CASE_BIND:                                                                             \
        _NET_EBPF_EXT_LOG_MESSAGE_UINT64(trace_level, KEYWORD_BIND, message, status);      \
        break;                                                                             \
    CASE_EXT:                                                                              \
        _NET_EBPF_EXT_LOG_MESSAGE_UINT64(trace_level, KEYWORD_EXT, message, status);       \
        break;                                                                             \
    CASE_SOCK_ADDR:                                                                        \
        _NET_EBPF_EXT_LOG_MESSAGE_UINT64(trace_level, KEYWORD_SOCK_ADDR, message, status); \
        break;                                                                             \
    CASE_SOCK_OPS:                                                                         \
        _NET_EBPF_EXT_LOG_MESSAGE_UINT64(trace_level, KEYWORD_SOCK_OPS, message, status);  \
        break;                                                                             \
    CASE_XDP:                                                                              \
        _NET_EBPF_EXT_LOG_MESSAGE_UINT64(trace_level, KEYWORD_XDP, message, status);       \
        break;                                                                             \
    default:                                                                               \
        ebpf_assert(!"Invalid keyword");                                                   \
        break;                                                                             \
    }

__declspec(noinline) void net_ebpf_ext_log_message_uint64(
    net_ebpf_ext_tracelog_level_t trace_level,
    net_ebpf_ext_tracelog_keyword_t keyword,
    _In_z_ const char* message,
    uint64_t value)
{
    switch (trace_level) {
    CASE_LOG_ALWAYS:
        NET_EBPF_EXT_LOG_MESSAGE_UINT64_KEYWORD_SWITCH(LEVEL_LOG_ALWAYS, message, value);
        break;
    CASE_CRITICAL:
        NET_EBPF_EXT_LOG_MESSAGE_UINT64_KEYWORD_SWITCH(LEVEL_CRITICAL, message, value);
        break;
    CASE_LEVEL_ERROR:
        NET_EBPF_EXT_LOG_MESSAGE_UINT64_KEYWORD_SWITCH(LEVEL_ERROR, message, value);
        break;
    CASE_WARNING:
        NET_EBPF_EXT_LOG_MESSAGE_UINT64_KEYWORD_SWITCH(LEVEL_WARNING, message, value);
        break;
    CASE_INFO:
        NET_EBPF_EXT_LOG_MESSAGE_UINT64_KEYWORD_SWITCH(LEVEL_INFO, message, value);
        break;
    CASE_VERBOSE:
        NET_EBPF_EXT_LOG_MESSAGE_UINT64_KEYWORD_SWITCH(LEVEL_VERBOSE, message, value);
        break;
    default:
        ebpf_assert(!"Invalid trace level");
        break;
    }
}

#define NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_UINT64_UINT64_KEYWORD_SWITCH(api_name, status, value1, value2)       \
    switch (keyword) {                                                                                             \
    CASE_BASE:                                                                                                     \
        _NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_UINT64_UINT64(KEYWORD_BASE, api_name, status, value1, value2);      \
        break;                                                                                                     \
    CASE_EXT:                                                                                                      \
        _NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_UINT64_UINT64(KEYWORD_EXT, api_name, status, value1, value2);       \
        break;                                                                                                     \
    CASE_BIND:                                                                                                     \
        _NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_UINT64_UINT64(KEYWORD_BIND, api_name, status, value1, value2);      \
        break;                                                                                                     \
    CASE_SOCK_ADDR:                                                                                                \
        _NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_UINT64_UINT64(KEYWORD_SOCK_ADDR, api_name, status, value1, value2); \
        break;                                                                                                     \
    CASE_SOCK_OPS:                                                                                                 \
        _NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_UINT64_UINT64(KEYWORD_SOCK_OPS, api_name, status, value1, value2);  \
        break;                                                                                                     \
    CASE_XDP:                                                                                                      \
        _NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_UINT64_UINT64(KEYWORD_XDP, api_name, status, value1, value2);       \
        break;                                                                                                     \
    default:                                                                                                       \
        ebpf_assert(!"Invalid keyword");                                                                           \
        break;                                                                                                     \
    }

__declspec(noinline) void net_ebpf_ext_log_ntstatus_api_failure_uint64_uint64(
    net_ebpf_ext_tracelog_keyword_t keyword,
    _In_z_ const char* api_name,
    NTSTATUS status,
    uint64_t value1,
    uint64_t value2)
{
    NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_UINT64_UINT64_KEYWORD_SWITCH(api_name, status, value1, value2);
}

#define NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_KEYWORD_SWITCH(trace_level, message, value1, value2)       \
    switch (keyword) {                                                                                    \
    CASE_BASE:                                                                                            \
        _NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64(trace_level, KEYWORD_BASE, message, value1, value2);      \
        break;                                                                                            \
    CASE_EXT:                                                                                             \
        _NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64(trace_level, KEYWORD_EXT, message, value1, value2);       \
        break;                                                                                            \
    CASE_BIND:                                                                                            \
        _NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64(trace_level, KEYWORD_BIND, message, value1, value2);      \
        break;                                                                                            \
    CASE_SOCK_ADDR:                                                                                       \
        _NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64(trace_level, KEYWORD_SOCK_ADDR, message, value1, value2); \
        break;                                                                                            \
    CASE_SOCK_OPS:                                                                                        \
        _NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64(trace_level, KEYWORD_SOCK_OPS, message, value1, value2);  \
        break;                                                                                            \
    CASE_XDP:                                                                                             \
        _NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64(trace_level, KEYWORD_XDP, message, value1, value2);       \
        break;                                                                                            \
    default:                                                                                              \
        ebpf_assert(!"Invalid keyword");                                                                  \
        break;                                                                                            \
    }

__declspec(noinline) void net_ebpf_ext_log_message_uint64_uint64(
    net_ebpf_ext_tracelog_level_t trace_level,
    net_ebpf_ext_tracelog_keyword_t keyword,
    _In_z_ const char* message,
    uint64_t value1,
    uint64_t value2)
{
    switch (trace_level) {
    CASE_LOG_ALWAYS:
        NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_KEYWORD_SWITCH(LEVEL_LOG_ALWAYS, message, value1, value2);
        break;
    CASE_CRITICAL:
        NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_KEYWORD_SWITCH(LEVEL_CRITICAL, message, value1, value2);
        break;
    CASE_LEVEL_ERROR:
        NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_KEYWORD_SWITCH(LEVEL_ERROR, message, value1, value2);
        break;
    CASE_WARNING:
        NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_KEYWORD_SWITCH(LEVEL_WARNING, message, value1, value2);
        break;
    CASE_INFO:
        NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_KEYWORD_SWITCH(LEVEL_INFO, message, value1, value2);
        break;
    CASE_VERBOSE:
        NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_KEYWORD_SWITCH(LEVEL_VERBOSE, message, value1, value2);
        break;
    default:
        ebpf_assert(!"Invalid trace level");
        break;
    }
}

#define NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_UINT64_KEYWORD_SWITCH(trace_level, message, value1, value2, value3)  \
    switch (keyword) {                                                                                              \
    CASE_BASE:                                                                                                      \
        _NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_UINT64(trace_level, KEYWORD_BASE, message, value1, value2, value3); \
        break;                                                                                                      \
    CASE_EXT:                                                                                                       \
        _NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_UINT64(trace_level, KEYWORD_EXT, message, value1, value2, value3);  \
        break;                                                                                                      \
    CASE_BIND:                                                                                                      \
        _NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_UINT64(trace_level, KEYWORD_BIND, message, value1, value2, value3); \
        break;                                                                                                      \
    CASE_SOCK_ADDR:                                                                                                 \
        _NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_UINT64(                                                             \
            trace_level, KEYWORD_SOCK_ADDR, message, value1, value2, value3);                                       \
        break;                                                                                                      \
    CASE_SOCK_OPS:                                                                                                  \
        _NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_UINT64(                                                             \
            trace_level, KEYWORD_SOCK_OPS, message, value1, value2, value3);                                        \
        break;                                                                                                      \
    CASE_XDP:                                                                                                       \
        _NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_UINT64(trace_level, KEYWORD_XDP, message, value1, value2, value3);  \
        break;                                                                                                      \
    default:                                                                                                        \
        ebpf_assert(!"Invalid keyword");                                                                            \
        break;                                                                                                      \
    }

__declspec(noinline) void net_ebpf_ext_log_message_uint64_uint64_uint64(
    net_ebpf_ext_tracelog_level_t trace_level,
    net_ebpf_ext_tracelog_keyword_t keyword,
    _In_z_ const char* message,
    uint64_t value1,
    uint64_t value2,
    uint64_t value3)
{
    switch (trace_level) {
    CASE_LOG_ALWAYS:
        NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_UINT64_KEYWORD_SWITCH(LEVEL_LOG_ALWAYS, message, value1, value2, value3);
        break;
    CASE_CRITICAL:
        NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_UINT64_KEYWORD_SWITCH(LEVEL_CRITICAL, message, value1, value2, value3);
        break;
    CASE_LEVEL_ERROR:
        NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_UINT64_KEYWORD_SWITCH(LEVEL_ERROR, message, value1, value2, value3);
        break;
    CASE_WARNING:
        NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_UINT64_KEYWORD_SWITCH(LEVEL_WARNING, message, value1, value2, value3);
        break;
    CASE_INFO:
        NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_UINT64_KEYWORD_SWITCH(LEVEL_INFO, message, value1, value2, value3);
        break;
    CASE_VERBOSE:
        NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_UINT64_KEYWORD_SWITCH(LEVEL_VERBOSE, message, value1, value2, value3);
        break;
    default:
        ebpf_assert(!"Invalid trace level");
        break;
    }
}
#pragma warning(pop)