// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf/bpf.h"
#include "ebpf_api.h"
#include "latency.h"
#include "platform.h"
#include "tokens.h"
#include "utilities.h"

#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <tuple>
#include <vector>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <evntcons.h>
#include <evntrace.h>
#include <netsh.h>
#include <stdio.h>
#include <strsafe.h>
#include <tdh.h>

#pragma comment(lib, "tdh.lib")

#define TOKEN_MODE L"mode"
#define TOKEN_PROGRAMS L"programs"
#define TOKEN_CORRELATION L"correlation"
#define TOKEN_EVENTS L"events"
#define TOKEN_BACKEND L"backend"
#define TOKEN_FILE L"file"

typedef enum
{
    LATENCY_MODE_OFF = 0,
    LATENCY_MODE_PROGRAM = 1,
    LATENCY_MODE_ALL = 2,
} LATENCY_MODE_VALUE;

static TOKEN_VALUE _latency_mode_enum[] = {
    {L"off", LATENCY_MODE_OFF},
    {L"program", LATENCY_MODE_PROGRAM},
    {L"all", LATENCY_MODE_ALL},
};

typedef enum
{
    CORRELATION_NO = 0,
    CORRELATION_YES = 1,
} CORRELATION_VALUE;

static TOKEN_VALUE _correlation_enum[] = {
    {L"no", CORRELATION_NO},
    {L"yes", CORRELATION_YES},
};

typedef enum
{
    BACKEND_RINGBUFFER = 0,
    BACKEND_ETW = 1,
} BACKEND_VALUE;

static TOKEN_VALUE _backend_enum[] = {
    {L"ringbuffer", BACKEND_RINGBUFFER},
    {L"etw", BACKEND_ETW},
};

// State tracking for the active latency backend.
static BACKEND_VALUE _active_backend = BACKEND_RINGBUFFER;
static bool _backend_active = false;
static WCHAR _active_etw_file[MAX_PATH] = {0};

// ETW trace session name for latency tracing.
static const WCHAR _ebpf_latency_session_name[] = L"EbpfLatencyTrace";

// EbpfForWindowsProvider {394f321c-5cf4-404c-aa34-4df1428a7f9c}
static const GUID _ebpf_core_provider_guid = {
    0x394f321c, 0x5cf4, 0x404c, {0xaa, 0x34, 0x4d, 0xf1, 0x42, 0x8a, 0x7f, 0x9c}};

// Latency keyword as defined in the design doc.
#define EBPF_TRACELOG_KEYWORD_LATENCY 0x800

// Default ETW session parameters.
#define DEFAULT_BUFFER_SIZE_KB 256
#define DEFAULT_MIN_BUFFERS 64
#define DEFAULT_MAX_BUFFERS 256
#define DEFAULT_FLUSH_TIMER_SEC 1
#define DEFAULT_OUTPUT_FILE L"ebpf_latency.etl"

// Helper: start an ETW trace session for latency events.
static unsigned long
_start_etw_session(_In_z_ LPCWSTR output_file, ULONG buffer_size_kb)
{
    ULONG properties_size =
        sizeof(EVENT_TRACE_PROPERTIES) + sizeof(_ebpf_latency_session_name) + (MAX_PATH * sizeof(WCHAR));
    EVENT_TRACE_PROPERTIES* properties = (EVENT_TRACE_PROPERTIES*)calloc(1, properties_size);
    if (properties == nullptr) {
        printf("Error: out of memory.\n");
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    properties->Wnode.BufferSize = properties_size;
    properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    properties->Wnode.ClientContext = 1; // QPC clock resolution.
    properties->BufferSize = buffer_size_kb;
    properties->MinimumBuffers = DEFAULT_MIN_BUFFERS;
    properties->MaximumBuffers = DEFAULT_MAX_BUFFERS;
    properties->FlushTimer = DEFAULT_FLUSH_TIMER_SEC;
    properties->LogFileMode = EVENT_TRACE_FILE_MODE_SEQUENTIAL;
    properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    properties->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(_ebpf_latency_session_name);

    StringCchCopyW((LPWSTR)((BYTE*)properties + properties->LogFileNameOffset), MAX_PATH, output_file);

    TRACEHANDLE session_handle = 0;
    unsigned long status = StartTraceW(&session_handle, _ebpf_latency_session_name, properties);
    if (status != ERROR_SUCCESS) {
        if (status == ERROR_ALREADY_EXISTS) {
            printf("Error: ETW trace session '%ls' is already running.\n", _ebpf_latency_session_name);
        } else {
            printf("Error: StartTrace failed (error=%lu).\n", status);
        }
        free(properties);
        return status;
    }

    ENABLE_TRACE_PARAMETERS enable_params = {0};
    enable_params.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
    status = EnableTraceEx2(
        session_handle,
        &_ebpf_core_provider_guid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE,
        EBPF_TRACELOG_KEYWORD_LATENCY,
        0,
        0,
        &enable_params);
    if (status != ERROR_SUCCESS) {
        printf("Warning: failed to enable EbpfForWindowsProvider (error=%lu).\n", status);
    }

    free(properties);
    return ERROR_SUCCESS;
}

// Helper: stop the ETW trace session.
static unsigned long
_stop_etw_session()
{
    ULONG properties_size =
        sizeof(EVENT_TRACE_PROPERTIES) + sizeof(_ebpf_latency_session_name) + (MAX_PATH * sizeof(WCHAR));
    EVENT_TRACE_PROPERTIES* properties = (EVENT_TRACE_PROPERTIES*)calloc(1, properties_size);
    if (properties == nullptr) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    properties->Wnode.BufferSize = properties_size;
    properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    properties->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(_ebpf_latency_session_name);

    unsigned long status = ControlTraceW(0, _ebpf_latency_session_name, properties, EVENT_TRACE_CONTROL_STOP);

    if (status == ERROR_SUCCESS) {
        LPCWSTR log_file_name = (LPCWSTR)((BYTE*)properties + properties->LogFileNameOffset);
        if (log_file_name[0] != L'\0') {
            printf("  ETW trace saved to: %ls\n", log_file_name);
        }
    }

    free(properties);
    return status;
}

unsigned long
handle_ebpf_set_latency(
    LPCWSTR machine, LPWSTR* argv, DWORD current_index, DWORD argc, DWORD flags, LPCVOID data, BOOL* done)
{
    UNREFERENCED_PARAMETER(machine);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(done);

    TAG_TYPE tags[] = {
        {TOKEN_MODE, NS_REQ_PRESENT, FALSE},
        {TOKEN_PROGRAMS, NS_REQ_ZERO, FALSE},
        {TOKEN_CORRELATION, NS_REQ_ZERO, FALSE},
        {TOKEN_EVENTS, NS_REQ_ZERO, FALSE},
        {TOKEN_BACKEND, NS_REQ_ZERO, FALSE},
        {TOKEN_FILE, NS_REQ_ZERO, FALSE},
    };
    const int MODE_INDEX = 0;
    const int PROGRAMS_INDEX = 1;
    const int CORRELATION_INDEX = 2;
    const int EVENTS_INDEX = 3;
    const int BACKEND_INDEX = 4;
    const int FILE_INDEX = 5;

    unsigned long tag_type[_countof(tags)] = {0};

    unsigned long status =
        PreprocessCommand(nullptr, argv, current_index, argc, tags, _countof(tags), 0, _countof(tags), tag_type);

    if (status != NO_ERROR) {
        return status;
    }

    uint32_t mode = LATENCY_MODE_OFF;
    std::vector<uint32_t> program_ids;
    uint32_t correlation = CORRELATION_NO;
    uint32_t events_per_cpu = 0; // 0 = use default.
    uint32_t backend = BACKEND_RINGBUFFER;
    WCHAR etw_file[MAX_PATH] = DEFAULT_OUTPUT_FILE;

    for (DWORD i = 0; (status == NO_ERROR) && ((i + current_index) < argc); i++) {
        switch (tag_type[i]) {
        case MODE_INDEX: {
            status = MatchEnumTag(
                nullptr,
                argv[current_index + i],
                _countof(_latency_mode_enum),
                _latency_mode_enum,
                (unsigned long*)&mode);
            if (status != NO_ERROR) {
                status = ERROR_INVALID_PARAMETER;
            }
            break;
        }
        case PROGRAMS_INDEX: {
            // Parse comma-separated list of program IDs: "3,7,12"
            LPWSTR token_context = nullptr;
            LPWSTR token = wcstok_s(argv[current_index + i], L",", &token_context);
            while (token != nullptr) {
                WCHAR* end_ptr = nullptr;
                unsigned long id = wcstoul(token, &end_ptr, 10);
                if (end_ptr == token || *end_ptr != L'\0') {
                    printf("Error: invalid program ID '%ls'.\n", token);
                    return ERROR_INVALID_PARAMETER;
                }
                program_ids.push_back(static_cast<uint32_t>(id));
                token = wcstok_s(nullptr, L",", &token_context);
            }
            break;
        }
        case CORRELATION_INDEX: {
            status = MatchEnumTag(
                nullptr,
                argv[current_index + i],
                _countof(_correlation_enum),
                _correlation_enum,
                (unsigned long*)&correlation);
            if (status != NO_ERROR) {
                status = ERROR_INVALID_PARAMETER;
            }
            break;
        }
        case EVENTS_INDEX: {
            WCHAR* end_ptr = nullptr;
            unsigned long val = wcstoul(argv[current_index + i], &end_ptr, 10);
            if (end_ptr == argv[current_index + i] || *end_ptr != L'\0' || val == 0) {
                printf("Error: invalid events value '%ls'. Must be a positive integer.\n", argv[current_index + i]);
                return ERROR_INVALID_PARAMETER;
            }
            events_per_cpu = static_cast<uint32_t>(val);
            break;
        }
        case BACKEND_INDEX: {
            status = MatchEnumTag(
                nullptr, argv[current_index + i], _countof(_backend_enum), _backend_enum, (unsigned long*)&backend);
            if (status != NO_ERROR) {
                status = ERROR_INVALID_PARAMETER;
            }
            break;
        }
        case FILE_INDEX:
            StringCchCopyW(etw_file, MAX_PATH, argv[current_index + i]);
            break;
        default:
            status = ERROR_INVALID_SYNTAX;
            break;
        }
    }

    if (status != NO_ERROR) {
        return status;
    }

    ebpf_result_t result;
    if (mode == LATENCY_MODE_OFF) {
        // Query kernel to determine the active backend.
        uint32_t cur_mode = 0, cur_backend = 0, cur_session = 0;
        ebpf_latency_tracking_query_state(&cur_mode, &cur_backend, &cur_session);
        bool is_etw = (cur_backend == EBPF_LATENCY_BACKEND_ETW);

        // Stop tracking.
        if (is_etw) {
            // Stop the ETW session first.
            _stop_etw_session();
        }

        result = ebpf_latency_tracking_disable();
        if (result == EBPF_SUCCESS) {
            if (is_etw) {
                // ETW: release session immediately (data is in the .etl file).
                ebpf_latency_tracking_release();
                printf("Latency tracking stopped.\n");
            } else {
                printf("Latency tracking disabled.\n");
                printf("Use 'netsh ebpf show latencytrace' to view collected data.\n");
            }
            _backend_active = false;
        }
    } else {
        // Validate mutual exclusivity: ETW backend does not use ring buffer buffer-size parameter.
        if (backend == BACKEND_ETW && events_per_cpu != 0) {
            printf("Error: 'events' parameter is only valid with backend=ringbuffer.\n");
            return ERROR_INVALID_PARAMETER;
        }

        // Release any zombie session from a previous run (disabled but not drained/released).
        ebpf_latency_tracking_release();

        uint32_t latency_flags = 0;
        if (correlation == CORRELATION_YES) {
            latency_flags |= EBPF_LATENCY_FLAG_CORRELATION_ID;
        }
        result = ebpf_latency_tracking_enable(
            mode,
            latency_flags,
            (backend == BACKEND_RINGBUFFER) ? events_per_cpu : 0,
            (backend == BACKEND_ETW) ? EBPF_LATENCY_BACKEND_ETW : EBPF_LATENCY_BACKEND_RINGBUFFER,
            static_cast<uint32_t>(program_ids.size()),
            program_ids.empty() ? nullptr : program_ids.data());
        if (result == EBPF_SUCCESS) {
            // If ETW backend, start the ETW trace session.
            if (backend == BACKEND_ETW) {
                unsigned long etw_status = _start_etw_session(etw_file, DEFAULT_BUFFER_SIZE_KB);
                if (etw_status != ERROR_SUCCESS) {
                    // Roll back: disable and release kernel tracking.
                    ebpf_latency_tracking_disable();
                    ebpf_latency_tracking_release();
                    printf("Error: failed to start ETW trace session.\n");
                    return ERROR_SUPPRESS_OUTPUT;
                }
                StringCchCopyW(_active_etw_file, MAX_PATH, etw_file);
            }

            _active_backend = (BACKEND_VALUE)backend;
            _backend_active = true;

            if (mode == LATENCY_MODE_PROGRAM) {
                printf("Latency tracking enabled (mode=program");
            } else {
                printf("Latency tracking enabled (mode=program+helpers");
            }
            printf(", backend=%s", (backend == BACKEND_ETW) ? "etw" : "ringbuffer");
            if (!program_ids.empty()) {
                printf(", filter=[");
                for (size_t j = 0; j < program_ids.size(); j++) {
                    if (j > 0) {
                        printf(", ");
                    }
                    printf("%u", program_ids[j]);
                }
                printf("]");
            } else {
                printf(", filter=all");
            }
            printf(", correlation=%s", (latency_flags & EBPF_LATENCY_FLAG_CORRELATION_ID) ? "yes" : "no");
            if (backend == BACKEND_ETW) {
                printf(", file=%ls", etw_file);
            }
            printf(").\n");
        } else if (result == EBPF_INVALID_STATE) {
            printf("Error: Another latency tracking session is already active.\n");
            printf("Use 'netsh ebpf set latency mode=off' first.\n");
            return ERROR_SUPPRESS_OUTPUT;
        }
    }

    if (result != EBPF_SUCCESS) {
        printf("Error: failed to set latency tracking mode (error=%d).\n", result);
        return ERROR_SUPPRESS_OUTPUT;
    }

    return NO_ERROR;
}

unsigned long
handle_ebpf_show_latency(
    LPCWSTR machine, LPWSTR* argv, DWORD current_index, DWORD argc, DWORD flags, LPCVOID data, BOOL* done)
{
    UNREFERENCED_PARAMETER(machine);
    UNREFERENCED_PARAMETER(argv);
    UNREFERENCED_PARAMETER(current_index);
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(done);

    printf("\nLatency Tracking Status:\n");

    uint32_t cur_mode = 0, cur_backend = 0, cur_session = 0;
    ebpf_result_t query_result = ebpf_latency_tracking_query_state(&cur_mode, &cur_backend, &cur_session);
    if (query_result == EBPF_SUCCESS && cur_session != 0) {
        const char* mode_str = (cur_mode == 2) ? "all" : (cur_mode == 1) ? "program" : "off";
        const char* backend_str = (cur_backend == EBPF_LATENCY_BACKEND_ETW) ? "etw" : "ringbuffer";
        printf("  Mode:    %s\n", mode_str);
        printf("  Backend: %s\n", backend_str);
        printf("  Session: active\n");
    } else {
        printf("  No active latency tracking session.\n");
    }
    printf("\n  Usage:\n");
    printf("    netsh ebpf set latency mode=all backend=ringbuffer [correlation=yes] [events=N]\n");
    printf("    netsh ebpf set latency mode=all backend=etw [correlation=yes] [file=output.etl]\n");
    printf("    netsh ebpf set latency mode=off\n");
    printf("    netsh ebpf show latencytrace [file=<path>] [format=table|csv]\n\n");

    return NO_ERROR;
}

#define TOKEN_BUFFERSIZE L"buffersize"

unsigned long
handle_ebpf_start_latencytrace(
    LPCWSTR machine, LPWSTR* argv, DWORD current_index, DWORD argc, DWORD flags, LPCVOID data, BOOL* done)
{
    UNREFERENCED_PARAMETER(machine);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(done);

    printf("Note: This command is deprecated. Use 'netsh ebpf set latency mode=all backend=etw' instead.\n\n");

    TAG_TYPE tags[] = {
        {TOKEN_FILE, NS_REQ_ZERO, FALSE},
        {TOKEN_BUFFERSIZE, NS_REQ_ZERO, FALSE},
    };
    const int FILE_INDEX = 0;
    const int BUFFERSIZE_INDEX = 1;

    unsigned long tag_type[_countof(tags)] = {0};

    unsigned long status =
        PreprocessCommand(nullptr, argv, current_index, argc, tags, _countof(tags), 0, _countof(tags), tag_type);

    if (status != NO_ERROR) {
        return status;
    }

    WCHAR output_file[MAX_PATH] = DEFAULT_OUTPUT_FILE;
    ULONG buffer_size_kb = DEFAULT_BUFFER_SIZE_KB;

    for (DWORD i = 0; (status == NO_ERROR) && ((i + current_index) < argc); i++) {
        switch (tag_type[i]) {
        case FILE_INDEX:
            StringCchCopyW(output_file, MAX_PATH, argv[current_index + i]);
            break;
        case BUFFERSIZE_INDEX:
            buffer_size_kb = wcstoul(argv[current_index + i], nullptr, 10);
            if (buffer_size_kb == 0) {
                printf("Error: invalid buffer size.\n");
                return ERROR_INVALID_PARAMETER;
            }
            break;
        default:
            status = ERROR_INVALID_SYNTAX;
            break;
        }
    }

    if (status != NO_ERROR) {
        return status;
    }

    unsigned long etw_status = _start_etw_session(output_file, buffer_size_kb);
    if (etw_status != ERROR_SUCCESS) {
        return ERROR_SUPPRESS_OUTPUT;
    }

    printf("Started ETW trace session '%ls'.\n", _ebpf_latency_session_name);
    printf("  Output:   %ls\n", output_file);
    printf("  Buffers:  %lu KB x %d-%d\n", buffer_size_kb, DEFAULT_MIN_BUFFERS, DEFAULT_MAX_BUFFERS);

    return NO_ERROR;
}

unsigned long
handle_ebpf_stop_latencytrace(
    LPCWSTR machine, LPWSTR* argv, DWORD current_index, DWORD argc, DWORD flags, LPCVOID data, BOOL* done)
{
    UNREFERENCED_PARAMETER(machine);
    UNREFERENCED_PARAMETER(argv);
    UNREFERENCED_PARAMETER(current_index);
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(done);

    printf("Note: This command is deprecated. Use 'netsh ebpf set latency mode=off' with backend=etw instead.\n\n");

    unsigned long status = _stop_etw_session();
    if (status != ERROR_SUCCESS) {
        if (status == ERROR_WMI_INSTANCE_NOT_FOUND) {
            printf("Error: ETW trace session '%ls' is not running.\n", _ebpf_latency_session_name);
        } else {
            printf("Error: ControlTrace(STOP) failed (error=%lu).\n", status);
        }
        return ERROR_SUPPRESS_OUTPUT;
    }

    printf("Stopped ETW trace session '%ls'.\n", _ebpf_latency_session_name);
    return NO_ERROR;
}

// ============================================================================
// show latencytrace — ETL file parser and latency report generator
// ============================================================================

// Conversion factor: 100-ns units to microseconds (100-ns * 100 = ns, / 1000 = us -> / 10).
#define FILETIME_UNITS_TO_US_DIVISOR 10

// BPF helper function ID to human-readable name mapping.
static const char*
_helper_function_name(uint32_t id)
{
    switch (id) {
    case 1:
        return "map_lookup_elem";
    case 2:
        return "map_update_elem";
    case 3:
        return "map_delete_elem";
    case 4:
        return "map_lookup_and_delete";
    case 11:
        return "ringbuf_output";
    case 16:
        return "map_push_elem";
    case 17:
        return "map_pop_elem";
    case 18:
        return "map_peek_elem";
    case 32:
        return "perf_event_output";
    default:
        return nullptr;
    }
}

// Resolve a set of program IDs to their names via BPF APIs.
// Returns a map from program_id -> program_name. If a program has been unloaded,
// its name will be empty.
static std::map<uint32_t, std::string>
_resolve_program_names(const std::set<uint32_t>& program_ids)
{
    std::map<uint32_t, std::string> names;
    for (uint32_t id : program_ids) {
        fd_t fd = bpf_prog_get_fd_by_id(id);
        if (fd >= 0) {
            struct bpf_prog_info info = {};
            uint32_t info_size = sizeof(info);
            if (bpf_obj_get_info_by_fd(fd, &info, &info_size) == 0) {
                names[id] = info.name;
            } else {
                names[id] = "";
            }
            Platform::_close(fd);
        } else {
            names[id] = "";
        }
    }
    return names;
}

// Resolve a set of map IDs to their names via BPF APIs.
// Returns a map from map_id -> map_name. If a map has been unloaded,
// its name will be empty.
static std::map<uint16_t, std::string>
_resolve_map_names(const std::set<uint16_t>& map_ids)
{
    std::map<uint16_t, std::string> names;
    for (uint16_t id : map_ids) {
        if (id == 0) {
            names[id] = "";
            continue;
        }
        fd_t fd = bpf_map_get_fd_by_id(id);
        if (fd >= 0) {
            struct bpf_map_info info = {};
            uint32_t info_size = sizeof(info);
            if (bpf_obj_get_info_by_fd(fd, &info, &info_size) == 0) {
                names[id] = info.name;
            } else {
                names[id] = "";
            }
            Platform::_close(fd);
        } else {
            names[id] = "";
        }
    }
    return names;
}

// Helper key type for grouping map helper durations by (program_id, helper_id, map_name).
typedef std::tuple<uint32_t, uint32_t, std::string> helper_key_t;

// Context passed through the ETW consumer callback.
typedef struct _latency_trace_context
{
    // program_id -> vector of durations (100-ns units).
    std::map<uint32_t, std::vector<uint64_t>> program_durations;

    // program_id -> program name (first name seen for each id).
    std::map<uint32_t, std::string> program_names;

    // (program_id, helper_id, map_name) -> vector of durations (100-ns units).
    std::map<helper_key_t, std::vector<uint64_t>> helper_durations;

    // Extension events: program_id -> vector of durations (100-ns units).
    std::map<uint32_t, std::vector<uint64_t>> ext_durations;

    uint64_t first_timestamp;  // QPC
    uint64_t last_timestamp;   // QPC
    uint64_t timer_resolution; // QPC frequency (ticks/sec)
    uint32_t total_events;
    bool csv_format;
} latency_trace_context_t;

// Extract a uint32 property from a TDH-decoded event by name.
static uint32_t
_get_uint32_property(_In_ PEVENT_RECORD event, _In_z_ LPCWSTR property_name)
{
    PROPERTY_DATA_DESCRIPTOR descriptor = {};
    descriptor.PropertyName = (ULONGLONG)property_name;
    descriptor.ArrayIndex = ULONG_MAX;

    uint32_t value = 0;
    ULONG buffer_size = sizeof(value);
    TdhGetProperty(event, 0, nullptr, 1, &descriptor, buffer_size, (PBYTE)&value);
    return value;
}

// Extract a uint64 property from a TDH-decoded event by name.
static uint64_t
_get_uint64_property(_In_ PEVENT_RECORD event, _In_z_ LPCWSTR property_name)
{
    PROPERTY_DATA_DESCRIPTOR descriptor = {};
    descriptor.PropertyName = (ULONGLONG)property_name;
    descriptor.ArrayIndex = ULONG_MAX;

    uint64_t value = 0;
    ULONG buffer_size = sizeof(value);
    TdhGetProperty(event, 0, nullptr, 1, &descriptor, buffer_size, (PBYTE)&value);
    return value;
}

// Extract a uint8 property from a TDH-decoded event by name.
static uint8_t
_get_uint8_property(_In_ PEVENT_RECORD event, _In_z_ LPCWSTR property_name)
{
    PROPERTY_DATA_DESCRIPTOR descriptor = {};
    descriptor.PropertyName = (ULONGLONG)property_name;
    descriptor.ArrayIndex = ULONG_MAX;

    uint8_t value = 0;
    ULONG buffer_size = sizeof(value);
    TdhGetProperty(event, 0, nullptr, 1, &descriptor, buffer_size, (PBYTE)&value);
    return value;
}

// Extract a string property from a TDH-decoded event by name.
static std::string
_get_string_property(_In_ PEVENT_RECORD event, _In_z_ LPCWSTR property_name)
{
    PROPERTY_DATA_DESCRIPTOR descriptor = {};
    descriptor.PropertyName = (ULONGLONG)property_name;
    descriptor.ArrayIndex = ULONG_MAX;

    ULONG property_size = 0;
    DWORD status = TdhGetPropertySize(event, 0, nullptr, 1, &descriptor, &property_size);
    if (status != ERROR_SUCCESS || property_size == 0) {
        return "";
    }

    std::string value(property_size, '\0');
    status = TdhGetProperty(event, 0, nullptr, 1, &descriptor, property_size, (PBYTE)value.data());
    if (status != ERROR_SUCCESS) {
        return "";
    }

    // Remove trailing null if present.
    while (!value.empty() && value.back() == '\0') {
        value.pop_back();
    }
    return value;
}

// Print a single event as a CSV row.
static void
_print_csv_event(
    _In_z_ const char* event_type,
    uint32_t program_id,
    _In_z_ const char* program_name,
    uint32_t helper_function_id,
    _In_z_ const char* map_name,
    uint32_t process_id,
    uint32_t thread_id,
    uint64_t start_time,
    uint64_t end_time,
    uint64_t duration,
    uint8_t cpu_id,
    uint8_t irql,
    uint64_t correlation_id)
{
    printf(
        "%s,%u,%s,%u,%s,%u,%u,%llu,%llu,%llu,%u,%u,%llu\n",
        event_type,
        program_id,
        program_name,
        helper_function_id,
        map_name,
        process_id,
        thread_id,
        (unsigned long long)start_time,
        (unsigned long long)end_time,
        (unsigned long long)(duration / FILETIME_UNITS_TO_US_DIVISOR),
        (unsigned)cpu_id,
        (unsigned)irql,
        (unsigned long long)correlation_id);
}

// ETW event record callback — called for each event in the .etl file.
static void WINAPI
_etl_event_record_callback(_In_ PEVENT_RECORD event_record)
{
    latency_trace_context_t* ctx = (latency_trace_context_t*)event_record->UserContext;

    // Filter by our provider GUIDs.
    // EbpfForWindowsProvider {394f321c-5cf4-404c-aa34-4df1428a7f9c}
    static const GUID ebpf_core_guid = {0x394f321c, 0x5cf4, 0x404c, {0xaa, 0x34, 0x4d, 0xf1, 0x42, 0x8a, 0x7f, 0x9c}};
    // NetEbpfExtProvider {f2f2ca01-ad02-4a07-9e90-95a2334f3692}
    static const GUID net_ebpf_ext_guid = {
        0xf2f2ca01, 0xad02, 0x4a07, {0x9e, 0x90, 0x95, 0xa2, 0x33, 0x4f, 0x36, 0x92}};

    bool is_core = IsEqualGUID(event_record->EventHeader.ProviderId, ebpf_core_guid);
    bool is_ext = IsEqualGUID(event_record->EventHeader.ProviderId, net_ebpf_ext_guid);

    if (!is_core && !is_ext) {
        return;
    }

    // Only process events with the latency keyword (0x800).
    if ((event_record->EventHeader.EventDescriptor.Keyword & 0x800) == 0) {
        return;
    }

    // Use TDH to get event information (including event name).
    DWORD buffer_size = 0;
    DWORD status = TdhGetEventInformation(event_record, 0, nullptr, nullptr, &buffer_size);
    if (status != ERROR_INSUFFICIENT_BUFFER) {
        return;
    }

    std::vector<BYTE> info_buffer(buffer_size);
    TRACE_EVENT_INFO* info = (TRACE_EVENT_INFO*)info_buffer.data();
    status = TdhGetEventInformation(event_record, 0, nullptr, info, &buffer_size);
    if (status != ERROR_SUCCESS) {
        return;
    }

    // Get event name from TraceLogging metadata.
    LPCWSTR event_name = (info->EventNameOffset != 0) ? (LPCWSTR)((BYTE*)info + info->EventNameOffset) : L"";

    // Track timestamps for duration calculation.
    uint64_t ts = event_record->EventHeader.TimeStamp.QuadPart;
    if (ctx->first_timestamp == 0 || ts < ctx->first_timestamp) {
        ctx->first_timestamp = ts;
    }
    if (ts > ctx->last_timestamp) {
        ctx->last_timestamp = ts;
    }

    if (is_core && wcscmp(event_name, L"EbpfProgramLatency") == 0) {
        uint32_t program_id = _get_uint32_property(event_record, L"ProgramId");
        std::string program_name_str = _get_string_property(event_record, L"ProgramName");
        uint64_t duration = _get_uint64_property(event_record, L"Duration");

        // Track program name (first seen wins).
        if (!program_name_str.empty() && ctx->program_names.find(program_id) == ctx->program_names.end()) {
            ctx->program_names[program_id] = program_name_str;
        }

        if (ctx->csv_format) {
            uint32_t helper_id = _get_uint32_property(event_record, L"HelperFunctionId");
            uint32_t process_id = _get_uint32_property(event_record, L"ProcessId");
            uint32_t thread_id = _get_uint32_property(event_record, L"ThreadId");
            uint64_t start_time = _get_uint64_property(event_record, L"StartTime");
            uint64_t end_time = _get_uint64_property(event_record, L"EndTime");
            uint8_t cpu_id = (uint8_t)_get_uint32_property(event_record, L"CpuId");
            uint8_t irql = (uint8_t)_get_uint32_property(event_record, L"Irql");
            uint64_t correlation_id = _get_uint64_property(event_record, L"CorrelationId");
            _print_csv_event(
                "ProgramInvoke",
                program_id,
                program_name_str.c_str(),
                helper_id,
                "",
                process_id,
                thread_id,
                start_time,
                end_time,
                duration,
                cpu_id,
                irql,
                correlation_id);
        } else {
            ctx->program_durations[program_id].push_back(duration);
        }
        ctx->total_events++;
    } else if (is_core && wcscmp(event_name, L"EbpfMapHelperLatency") == 0) {
        uint32_t program_id = _get_uint32_property(event_record, L"ProgramId");
        uint32_t helper_id = _get_uint32_property(event_record, L"HelperFunctionId");
        std::string map_name_str = _get_string_property(event_record, L"MapName");
        uint64_t duration = _get_uint64_property(event_record, L"Duration");

        if (ctx->csv_format) {
            uint32_t process_id = _get_uint32_property(event_record, L"ProcessId");
            uint32_t thread_id = _get_uint32_property(event_record, L"ThreadId");
            uint64_t start_time = _get_uint64_property(event_record, L"StartTime");
            uint64_t end_time = _get_uint64_property(event_record, L"EndTime");
            uint8_t cpu_id = (uint8_t)_get_uint32_property(event_record, L"CpuId");
            uint8_t irql = (uint8_t)_get_uint32_property(event_record, L"Irql");
            uint64_t correlation_id = _get_uint64_property(event_record, L"CorrelationId");
            _print_csv_event(
                "MapHelper",
                program_id,
                "",
                helper_id,
                map_name_str.c_str(),
                process_id,
                thread_id,
                start_time,
                end_time,
                duration,
                cpu_id,
                irql,
                correlation_id);
        } else {
            ctx->helper_durations[{program_id, helper_id, map_name_str}].push_back(duration);
        }
        ctx->total_events++;
    } else if (is_ext && wcscmp(event_name, L"NetEbpfExtInvokeLatency") == 0) {
        uint32_t program_id = _get_uint32_property(event_record, L"ProgramId");
        uint64_t duration = _get_uint64_property(event_record, L"ExtDuration");

        if (ctx->csv_format) {
            uint32_t hook_type = _get_uint32_property(event_record, L"HookType");
            uint32_t process_id = _get_uint32_property(event_record, L"ProcessId");
            uint32_t thread_id = _get_uint32_property(event_record, L"ThreadId");
            uint64_t start_time = _get_uint64_property(event_record, L"ExtStartTime");
            uint64_t end_time = _get_uint64_property(event_record, L"ExtEndTime");
            uint8_t cpu_id = _get_uint8_property(event_record, L"CpuId");
            _print_csv_event(
                "ExtInvoke",
                program_id,
                "",
                hook_type,
                "",
                process_id,
                thread_id,
                start_time,
                end_time,
                duration,
                cpu_id,
                0,
                0);
        } else {
            ctx->ext_durations[program_id].push_back(duration);
        }
        ctx->total_events++;
    }
}

// Compute statistics from a sorted vector of durations (100-ns units).
// Returns results in microseconds.
static void
_compute_stats(
    _Inout_ std::vector<uint64_t>& durations,
    _Out_ uint64_t* avg_us,
    _Out_ uint64_t* p50_us,
    _Out_ uint64_t* p95_us,
    _Out_ uint64_t* p99_us,
    _Out_ uint64_t* max_us)
{
    std::sort(durations.begin(), durations.end());
    size_t n = durations.size();
    if (n == 0) {
        *avg_us = *p50_us = *p95_us = *p99_us = *max_us = 0;
        return;
    }

    uint64_t sum = 0;
    for (auto d : durations) {
        sum += d;
    }
    *avg_us = (sum / n) / FILETIME_UNITS_TO_US_DIVISOR;
    *p50_us = durations[n * 50 / 100] / FILETIME_UNITS_TO_US_DIVISOR;
    *p95_us = durations[n * 95 / 100] / FILETIME_UNITS_TO_US_DIVISOR;
    *p99_us = durations[n * 99 / 100] / FILETIME_UNITS_TO_US_DIVISOR;
    *max_us = durations[n - 1] / FILETIME_UNITS_TO_US_DIVISOR;
}

// Format a number with thousands-separator commas (e.g. 1234567 -> "1,234,567").
static std::string
_format_number(uint64_t value)
{
    std::string raw = std::to_string(value);
    std::string result;
    int count = 0;
    for (auto it = raw.rbegin(); it != raw.rend(); ++it) {
        if (count > 0 && count % 3 == 0) {
            result.insert(result.begin(), ',');
        }
        result.insert(result.begin(), *it);
        count++;
    }
    return result;
}

// Format a double microsecond value as a string with 2 decimal places.
static std::string
_format_us(double us_value)
{
    char buf[64];
    sprintf_s(buf, sizeof(buf), "%.2f", us_value);
    return std::string(buf);
}

#define TOKEN_FORMAT L"format"
#define TOKEN_INPUT L"input"

typedef enum
{
    FORMAT_TABLE = 0,
    FORMAT_CSV = 1,
} FORMAT_VALUE;

static TOKEN_VALUE _format_enum[] = {
    {L"table", FORMAT_TABLE},
    {L"csv", FORMAT_CSV},
};

// ============================================================================
// show latencytrace — Ring buffer drain OR ETL file parser
// ============================================================================

// Forward declaration for ETL file processing.
static unsigned long
_show_latencytrace_from_etl(_In_z_ LPCWSTR etl_file, uint32_t format);

// Binary file header for latency trace output.
#define EBPF_LATENCY_FILE_MAGIC 0x544C4245 // "EBLT"
#define EBPF_LATENCY_FILE_VERSION 2

// Name table entry types.
#define EBPF_LATENCY_NAME_TYPE_PROGRAM 0
#define EBPF_LATENCY_NAME_TYPE_MAP 1

#pragma pack(push, 1)
typedef struct _ebpf_latency_file_header
{
    uint32_t magic;
    uint32_t version;
    uint64_t tsc_frequency;
    uint64_t tsc_at_enable;
    uint64_t qpc_at_enable;
    uint32_t cpu_count;
    uint32_t total_records;
    uint32_t name_table_entries;
    uint32_t reserved;
} ebpf_latency_file_header_t;

typedef struct _ebpf_latency_name_entry
{
    uint8_t type;         // EBPF_LATENCY_NAME_TYPE_PROGRAM or EBPF_LATENCY_NAME_TYPE_MAP.
    uint32_t id;          // program_id or map_id.
    uint16_t name_length; // byte count of name (no null terminator).
    // Followed by name_length bytes of UTF-8 name.
} ebpf_latency_name_entry_t;
#pragma pack(pop)

// Wire-format drain reply header. Must match the natural alignment of
// ebpf_operation_latency_drain_reply_t in ebpf_protocol.h (NOT packed).
typedef struct _latency_drain_reply_wire
{
    uint16_t length;
    uint16_t id;
    uint64_t tsc_frequency;
    uint64_t tsc_at_enable;
    uint64_t qpc_at_enable;
    uint32_t cpu_count;
    uint32_t records_per_cpu;
    uint32_t total_records;
    uint32_t dropped_count;
    uint32_t records_returned;
    uint32_t _padding;
    ebpf_latency_drain_record_t records[1];
} latency_drain_reply_wire_t;

// Drain ring buffers via chunked per-CPU IOCTLs, merge-sort, write file, display summary.
static unsigned long
_show_latencytrace_from_ringbuffer(uint32_t format, _In_opt_z_ const char* output_path)
{
    UNREFERENCED_PARAMETER(format);

    const char* output_file = (output_path != nullptr && output_path[0] != '\0') ? output_path : "ebpf_latency.bin";

    // Step 1: Probe with CPU 0 to get metadata and check state.
    uint32_t reply_size = 65535;
    std::vector<uint8_t> reply_buffer(reply_size);
    uint32_t actual_size = reply_size;

    ebpf_result_t result = ebpf_latency_tracking_drain(0, 0, reply_buffer.data(), &actual_size);
    if (result != EBPF_SUCCESS) {
        if (result == EBPF_BLOCKED_BY_POLICY) {
            printf("Error: Latency tracking is still enabled.\n");
            printf("Use 'netsh ebpf set latency mode=off' to stop tracking first.\n");
        } else if (result == EBPF_INVALID_STATE) {
            printf("Error: No active latency tracking session.\n");
            printf("Use 'netsh ebpf set latency mode=all' to enable tracking first.\n");
        } else {
            printf("Error: Failed to drain latency ring buffers (error=%d).\n", result);
        }
        return ERROR_SUPPRESS_OUTPUT;
    }

    // Parse the reply header to get cpu_count and calibration.
    auto* first_reply = reinterpret_cast<latency_drain_reply_wire_t*>(reply_buffer.data());
    uint32_t cpu_count = first_reply->cpu_count;
    uint32_t records_per_cpu = first_reply->records_per_cpu;
    uint64_t tsc_frequency = first_reply->tsc_frequency;
    uint64_t tsc_at_enable = first_reply->tsc_at_enable;
    uint64_t qpc_at_enable = first_reply->qpc_at_enable;

    printf("Draining latency data: %u CPUs, %u records/CPU buffer\n", cpu_count, records_per_cpu);

    // Step 2: Drain all CPUs. Collect records per-CPU.
    std::vector<std::vector<ebpf_latency_drain_record_t>> per_cpu_records(cpu_count);
    uint32_t total_records = 0;
    uint32_t total_dropped = 0;

    for (uint32_t cpu = 0; cpu < cpu_count; cpu++) {
        uint32_t offset = 0;
        bool first_call = (cpu == 0 && offset == 0); // We already have CPU 0's first chunk.

        if (first_call) {
            // Use the data we already fetched.
            uint32_t returned = first_reply->records_returned;
            auto* recs = reinterpret_cast<ebpf_latency_drain_record_t*>(first_reply->records);
            for (uint32_t j = 0; j < returned; j++) {
                per_cpu_records[cpu].push_back(recs[j]);
            }
            offset = returned;
            total_dropped += first_reply->dropped_count;

            if (returned == 0 || offset >= first_reply->total_records) {
                printf(
                    "  CPU %u: %u records, %u dropped\n", cpu, first_reply->total_records, first_reply->dropped_count);
                total_records += first_reply->total_records;
                continue;
            }
        }

        // Drain remaining chunks for this CPU.
        for (;;) {
            actual_size = reply_size;
            result = ebpf_latency_tracking_drain(cpu, offset, reply_buffer.data(), &actual_size);
            if (result != EBPF_SUCCESS) {
                printf("  CPU %u: drain failed at offset %u (error=%d)\n", cpu, offset, result);
                break;
            }

            auto* chunk = reinterpret_cast<latency_drain_reply_wire_t*>(reply_buffer.data());
            uint32_t returned = chunk->records_returned;
            if (returned == 0) {
                break;
            }

            auto* recs = reinterpret_cast<ebpf_latency_drain_record_t*>(chunk->records);
            for (uint32_t j = 0; j < returned; j++) {
                per_cpu_records[cpu].push_back(recs[j]);
            }
            offset += returned;

            if (offset >= chunk->total_records) {
                if (!first_call || cpu > 0) {
                    total_dropped += chunk->dropped_count;
                }
                break;
            }
        }

        printf("  CPU %u: %zu records read\n", cpu, per_cpu_records[cpu].size());
        total_records += static_cast<uint32_t>(per_cpu_records[cpu].size());
    }

    if (total_records == 0) {
        printf("No latency records collected.\n");
        ebpf_latency_tracking_release();
        return NO_ERROR;
    }

    printf("Total: %u records, %u dropped\n", total_records, total_dropped);

    // Step 3: Merge-sort all per-CPU records by timestamp.
    printf("Sorting records by timestamp...\n");
    std::vector<ebpf_latency_drain_record_t> all_records;
    all_records.reserve(total_records);
    for (uint32_t cpu = 0; cpu < cpu_count; cpu++) {
        all_records.insert(all_records.end(), per_cpu_records[cpu].begin(), per_cpu_records[cpu].end());
        // Free per-CPU memory now.
        per_cpu_records[cpu].clear();
        per_cpu_records[cpu].shrink_to_fit();
    }
    std::sort(
        all_records.begin(),
        all_records.end(),
        [](const ebpf_latency_drain_record_t& a, const ebpf_latency_drain_record_t& b) {
            return a.timestamp < b.timestamp;
        });

    // Step 4: Collect unique program and map IDs and resolve names.
    std::set<uint32_t> unique_program_ids;
    std::set<uint16_t> unique_map_ids;
    for (const auto& r : all_records) {
        if (r.program_id != 0) {
            unique_program_ids.insert(r.program_id);
        }
        if (r.map_id != 0) {
            unique_map_ids.insert(r.map_id);
        }
    }

    printf("Resolving %zu program IDs and %zu map IDs...\n", unique_program_ids.size(), unique_map_ids.size());
    auto program_names = _resolve_program_names(unique_program_ids);
    auto map_names = _resolve_map_names(unique_map_ids);

    // Step 5: Write sorted records + name table to file.
    FILE* fp = NULL;
    errno_t err = fopen_s(&fp, output_file, "wb");
    if (err != 0 || fp == NULL) {
        printf("Warning: Could not open '%s' for writing (error=%d). Skipping file output.\n", output_file, err);
    } else {
        // Count name table entries.
        uint32_t name_entries = (uint32_t)(program_names.size() + map_names.size());

        ebpf_latency_file_header_t file_header = {};
        file_header.magic = EBPF_LATENCY_FILE_MAGIC;
        file_header.version = EBPF_LATENCY_FILE_VERSION;
        file_header.tsc_frequency = tsc_frequency;
        file_header.tsc_at_enable = tsc_at_enable;
        file_header.qpc_at_enable = qpc_at_enable;
        file_header.cpu_count = cpu_count;
        file_header.total_records = total_records;
        file_header.name_table_entries = name_entries;
        file_header.reserved = 0;
        fwrite(&file_header, sizeof(file_header), 1, fp);
        fwrite(all_records.data(), sizeof(ebpf_latency_drain_record_t), all_records.size(), fp);

        // Write name table.
        for (const auto& [pid, name] : program_names) {
            ebpf_latency_name_entry_t entry = {};
            entry.type = EBPF_LATENCY_NAME_TYPE_PROGRAM;
            entry.id = pid;
            entry.name_length = (uint16_t)name.size();
            fwrite(&entry, sizeof(entry), 1, fp);
            fwrite(name.data(), 1, name.size(), fp);
        }
        for (const auto& [mid, name] : map_names) {
            ebpf_latency_name_entry_t entry = {};
            entry.type = EBPF_LATENCY_NAME_TYPE_MAP;
            entry.id = (uint32_t)mid;
            entry.name_length = (uint16_t)name.size();
            fwrite(&entry, sizeof(entry), 1, fp);
            fwrite(name.data(), 1, name.size(), fp);
        }

        fclose(fp);
        printf("Wrote %u sorted records + %u names to '%s'\n", total_records, name_entries, output_file);
    }

    // Step 6: Compute and display summary statistics.
    printf("\n=== eBPF Latency Report (Ring Buffer) ===\n\n");

    // Timestamps are in 100-ns units. Convert to microseconds by dividing by 10.
    auto ticks_to_us = [](uint64_t ticks_100ns) -> double { return (double)ticks_100ns / 10.0; };

    // Pair program start/end events per CPU to compute durations.
    std::map<uint32_t, std::vector<uint64_t>> program_durations;
    std::map<uint8_t, std::map<uint32_t, uint64_t>> cpu_prog_start;

    // Helper key: (program_id, helper_function_id, map_id).
    typedef std::tuple<uint32_t, uint16_t, uint16_t> rb_helper_key_t;
    std::map<rb_helper_key_t, std::vector<uint64_t>> helper_durations;
    // Track helper start timestamps per CPU: cpu_id -> (program_id, helper_id, map_id) -> timestamp.
    typedef std::tuple<uint32_t, uint16_t, uint16_t> helper_start_key_t;
    std::map<uint8_t, std::map<helper_start_key_t, uint64_t>> cpu_helper_start;

    for (const auto& r : all_records) {
        if (r.event_type == EBPF_LATENCY_EVENT_PROGRAM_START) {
            cpu_prog_start[r.cpu_id][r.program_id] = r.timestamp;
        } else if (r.event_type == EBPF_LATENCY_EVENT_PROGRAM_END) {
            auto cpu_it = cpu_prog_start.find(r.cpu_id);
            if (cpu_it != cpu_prog_start.end()) {
                auto prog_it = cpu_it->second.find(r.program_id);
                if (prog_it != cpu_it->second.end() && r.timestamp >= prog_it->second) {
                    program_durations[r.program_id].push_back(r.timestamp - prog_it->second);
                    cpu_it->second.erase(prog_it);
                }
            }
        } else if (r.event_type == EBPF_LATENCY_EVENT_HELPER_START) {
            helper_start_key_t key = {r.program_id, r.helper_function_id, r.map_id};
            cpu_helper_start[r.cpu_id][key] = r.timestamp;
        } else if (r.event_type == EBPF_LATENCY_EVENT_HELPER_END) {
            helper_start_key_t key = {r.program_id, r.helper_function_id, r.map_id};
            auto cpu_it = cpu_helper_start.find(r.cpu_id);
            if (cpu_it != cpu_helper_start.end()) {
                auto hlp_it = cpu_it->second.find(key);
                if (hlp_it != cpu_it->second.end() && r.timestamp >= hlp_it->second) {
                    rb_helper_key_t duration_key = {r.program_id, r.helper_function_id, r.map_id};
                    helper_durations[duration_key].push_back(r.timestamp - hlp_it->second);
                    cpu_it->second.erase(hlp_it);
                }
            }
        }
    }

    if (!program_durations.empty()) {
        // Compute dynamic column widths for program table.
        int id_w = 6;   // "ProgID"
        int name_w = 4; // "Name"
        int cnt_w = 5;  // "Count"
        int num_w = 8;  // "Avg (us)" etc.
        for (auto& [pid, durations] : program_durations) {
            std::sort(durations.begin(), durations.end());
            size_t n = durations.size();
            uint64_t sum = 0;
            for (auto d : durations)
                sum += d;

            char id_buf[16];
            sprintf_s(id_buf, sizeof(id_buf), "%u", pid);
            id_w = (std::max)(id_w, (int)strlen(id_buf));
            auto name_it = program_names.find(pid);
            if (name_it != program_names.end()) {
                name_w = (std::max)(name_w, (int)name_it->second.size());
            }
            cnt_w = (std::max)(cnt_w, (int)std::to_string(n).size());
            num_w = (std::max)(num_w, (int)_format_us(ticks_to_us(sum / n)).size());
            num_w = (std::max)(num_w, (int)_format_us(ticks_to_us(durations[n - 1])).size());
        }

        printf("--- Program Invocation Latency (us) ---\n");
        printf(
            "%-*s %-*s %*s %*s %*s %*s %*s %*s\n",
            id_w,
            "ProgID",
            name_w,
            "Name",
            cnt_w,
            "Count",
            num_w,
            "Avg (us)",
            num_w,
            "P50 (us)",
            num_w,
            "P90 (us)",
            num_w,
            "P99 (us)",
            num_w,
            "Max (us)");

        for (auto& [pid, durations] : program_durations) {
            size_t n = durations.size();
            uint64_t sum = 0;
            for (auto d : durations)
                sum += d;

            auto name_it = program_names.find(pid);
            const char* prog_name = (name_it != program_names.end()) ? name_it->second.c_str() : "";

            printf(
                "%-*u %-*s %*zu %*s %*s %*s %*s %*s\n",
                id_w,
                pid,
                name_w,
                prog_name,
                cnt_w,
                n,
                num_w,
                _format_us(ticks_to_us(sum / n)).c_str(),
                num_w,
                _format_us(ticks_to_us(durations[n * 50 / 100])).c_str(),
                num_w,
                _format_us(ticks_to_us(durations[n * 90 / 100])).c_str(),
                num_w,
                _format_us(ticks_to_us(durations[n * 99 / 100])).c_str(),
                num_w,
                _format_us(ticks_to_us(durations[n - 1])).c_str());
        }
    }

    // Helper latency table (grouped by program).
    if (!helper_durations.empty()) {
        // Group by program_id.
        std::map<uint32_t, std::vector<std::tuple<uint16_t, uint16_t, std::vector<uint64_t>*>>> by_program;
        for (auto& [key, durations] : helper_durations) {
            auto& [pid, hid, mid] = key;
            by_program[pid].push_back({hid, mid, &durations});
        }

        for (auto& [pid, helpers] : by_program) {
            auto prog_name_it = program_names.find(pid);
            if (prog_name_it != program_names.end() && !prog_name_it->second.empty()) {
                printf("\n--- Map Helper Summary (Program %u - %s) (us) ---\n", pid, prog_name_it->second.c_str());
            } else {
                printf("\n--- Map Helper Summary (Program %u) (us) ---\n", pid);
            }

            // Compute dynamic column widths for this program's helper table.
            int hlp_w = 6; // "Helper"
            int mid_w = 5; // "MapID"
            int map_w = 8; // "Map Name"
            int cnt_w = 5; // "Count"
            int num_w = 8; // "Avg (us)" etc.
            for (auto& [hid, mid, durations_ptr] : helpers) {
                std::sort(durations_ptr->begin(), durations_ptr->end());
                size_t n = durations_ptr->size();
                uint64_t sum = 0;
                for (auto d : *durations_ptr)
                    sum += d;

                const char* helper_name = _helper_function_name(hid);
                char helper_name_buf[32];
                if (helper_name == nullptr) {
                    sprintf_s(helper_name_buf, sizeof(helper_name_buf), "helper_%u", hid);
                    helper_name = helper_name_buf;
                }
                hlp_w = (std::max)(hlp_w, (int)strlen(helper_name));

                char mid_buf[16];
                sprintf_s(mid_buf, sizeof(mid_buf), "%u", (unsigned)mid);
                mid_w = (std::max)(mid_w, (int)strlen(mid_buf));

                auto map_name_it = map_names.find(mid);
                const char* map_name_str = (map_name_it != map_names.end()) ? map_name_it->second.c_str() : "";
                map_w = (std::max)(map_w, (int)strlen(map_name_str));

                cnt_w = (std::max)(cnt_w, (int)std::to_string(n).size());
                num_w = (std::max)(num_w, (int)_format_us(ticks_to_us(sum / n)).size());
                num_w = (std::max)(num_w, (int)_format_us(ticks_to_us((*durations_ptr)[n - 1])).size());
            }

            printf(
                "%-*s %*s %-*s %*s %*s %*s %*s %*s %*s\n",
                hlp_w,
                "Helper",
                mid_w,
                "MapID",
                map_w,
                "Map Name",
                cnt_w,
                "Count",
                num_w,
                "Avg (us)",
                num_w,
                "P50 (us)",
                num_w,
                "P90 (us)",
                num_w,
                "P99 (us)",
                num_w,
                "Max (us)");

            for (auto& [hid, mid, durations_ptr] : helpers) {
                size_t n = durations_ptr->size();
                uint64_t sum = 0;
                for (auto d : *durations_ptr)
                    sum += d;

                auto map_name_it = map_names.find(mid);
                const char* map_name_str = (map_name_it != map_names.end()) ? map_name_it->second.c_str() : "";

                const char* helper_name = _helper_function_name(hid);
                char helper_name_buf[32];
                if (helper_name == nullptr) {
                    sprintf_s(helper_name_buf, sizeof(helper_name_buf), "helper_%u", hid);
                    helper_name = helper_name_buf;
                }

                printf(
                    "%-*s %*u %-*s %*zu %*s %*s %*s %*s %*s\n",
                    hlp_w,
                    helper_name,
                    mid_w,
                    (unsigned)mid,
                    map_w,
                    map_name_str,
                    cnt_w,
                    n,
                    num_w,
                    _format_us(ticks_to_us(sum / n)).c_str(),
                    num_w,
                    _format_us(ticks_to_us((*durations_ptr)[n * 50 / 100])).c_str(),
                    num_w,
                    _format_us(ticks_to_us((*durations_ptr)[n * 90 / 100])).c_str(),
                    num_w,
                    _format_us(ticks_to_us((*durations_ptr)[n * 99 / 100])).c_str(),
                    num_w,
                    _format_us(ticks_to_us((*durations_ptr)[n - 1])).c_str());
            }
        }
    }

    // Step 7: Release session (free kernel ring buffers).
    ebpf_latency_tracking_release();
    printf("\nSession released.\n");

    return NO_ERROR;
}

// Re-parse a previously saved .bin file and display summary statistics.
static unsigned long
_show_latencytrace_from_bin(_In_z_ const WCHAR* bin_path, uint32_t format)
{
    UNREFERENCED_PARAMETER(format);

    // Open the file.
    char narrow_path[MAX_PATH] = {0};
    WideCharToMultiByte(CP_ACP, 0, bin_path, -1, narrow_path, MAX_PATH, nullptr, nullptr);

    FILE* fp = NULL;
    errno_t err = fopen_s(&fp, narrow_path, "rb");
    if (err != 0 || fp == NULL) {
        printf("Error: cannot open file '%s' (error=%d).\n", narrow_path, err);
        return ERROR_SUPPRESS_OUTPUT;
    }

    // Read and validate header.
    ebpf_latency_file_header_t file_header = {};
    if (fread(&file_header, sizeof(file_header), 1, fp) != 1) {
        printf("Error: failed to read file header from '%s'.\n", narrow_path);
        fclose(fp);
        return ERROR_SUPPRESS_OUTPUT;
    }

    if (file_header.magic != EBPF_LATENCY_FILE_MAGIC) {
        printf(
            "Error: invalid file magic (expected 0x%08X, got 0x%08X).\n", EBPF_LATENCY_FILE_MAGIC, file_header.magic);
        fclose(fp);
        return ERROR_SUPPRESS_OUTPUT;
    }

    if (file_header.version != EBPF_LATENCY_FILE_VERSION) {
        printf("Error: unsupported file version %u (expected %u).\n", file_header.version, EBPF_LATENCY_FILE_VERSION);
        fclose(fp);
        return ERROR_SUPPRESS_OUTPUT;
    }

    uint32_t total_records = file_header.total_records;
    printf("Reading %u records from '%s'...\n", total_records, narrow_path);

    // Read all records.
    std::vector<ebpf_latency_drain_record_t> all_records(total_records);
    size_t records_read = fread(all_records.data(), sizeof(ebpf_latency_drain_record_t), total_records, fp);

    if (records_read != total_records) {
        printf("Warning: expected %u records but read %zu.\n", total_records, records_read);
        all_records.resize(records_read);
    }

    // Collect unique program and map IDs.
    std::set<uint32_t> unique_program_ids;
    std::set<uint16_t> unique_map_ids;
    for (const auto& r : all_records) {
        if (r.program_id != 0) {
            unique_program_ids.insert(r.program_id);
        }
        if (r.map_id != 0) {
            unique_map_ids.insert(r.map_id);
        }
    }

    // Read embedded name table from file.
    std::map<uint32_t, std::string> program_names;
    std::map<uint16_t, std::string> map_names;
    uint32_t name_entries = file_header.name_table_entries;
    for (uint32_t i = 0; i < name_entries; i++) {
        ebpf_latency_name_entry_t entry = {};
        if (fread(&entry, sizeof(entry), 1, fp) != 1) {
            printf("Warning: truncated name table at entry %u.\n", i);
            break;
        }
        std::string name(entry.name_length, '\0');
        if (entry.name_length > 0 && fread(&name[0], 1, entry.name_length, fp) != entry.name_length) {
            printf("Warning: truncated name data at entry %u.\n", i);
            break;
        }
        if (entry.type == EBPF_LATENCY_NAME_TYPE_PROGRAM) {
            program_names[entry.id] = std::move(name);
        } else if (entry.type == EBPF_LATENCY_NAME_TYPE_MAP) {
            map_names[(uint16_t)entry.id] = std::move(name);
        }
    }
    fclose(fp);

    if (program_names.empty() && map_names.empty()) {
        printf("No embedded name table found; names will show as IDs only.\n");
    } else {
        printf("Loaded %zu program names and %zu map names from file.\n", program_names.size(), map_names.size());
    }

    // Compute and display summary statistics.
    printf("\n=== eBPF Latency Report (from %s) ===\n\n", narrow_path);

    // Timestamps are in 100-ns units. Convert to microseconds by dividing by 10.
    auto ticks_to_us = [](uint64_t ticks_100ns) -> double { return (double)ticks_100ns / 10.0; };

    // Pair program start/end events per CPU to compute durations.
    std::map<uint32_t, std::vector<uint64_t>> program_durations;
    std::map<uint8_t, std::map<uint32_t, uint64_t>> cpu_prog_start;

    // Helper key: (program_id, helper_function_id, map_id).
    typedef std::tuple<uint32_t, uint16_t, uint16_t> rb_helper_key_t;
    std::map<rb_helper_key_t, std::vector<uint64_t>> helper_durations;
    typedef std::tuple<uint32_t, uint16_t, uint16_t> helper_start_key_t;
    std::map<uint8_t, std::map<helper_start_key_t, uint64_t>> cpu_helper_start;

    for (const auto& r : all_records) {
        if (r.event_type == EBPF_LATENCY_EVENT_PROGRAM_START) {
            cpu_prog_start[r.cpu_id][r.program_id] = r.timestamp;
        } else if (r.event_type == EBPF_LATENCY_EVENT_PROGRAM_END) {
            auto cpu_it = cpu_prog_start.find(r.cpu_id);
            if (cpu_it != cpu_prog_start.end()) {
                auto prog_it = cpu_it->second.find(r.program_id);
                if (prog_it != cpu_it->second.end() && r.timestamp >= prog_it->second) {
                    program_durations[r.program_id].push_back(r.timestamp - prog_it->second);
                    cpu_it->second.erase(prog_it);
                }
            }
        } else if (r.event_type == EBPF_LATENCY_EVENT_HELPER_START) {
            helper_start_key_t key = {r.program_id, r.helper_function_id, r.map_id};
            cpu_helper_start[r.cpu_id][key] = r.timestamp;
        } else if (r.event_type == EBPF_LATENCY_EVENT_HELPER_END) {
            helper_start_key_t key = {r.program_id, r.helper_function_id, r.map_id};
            auto cpu_it = cpu_helper_start.find(r.cpu_id);
            if (cpu_it != cpu_helper_start.end()) {
                auto hlp_it = cpu_it->second.find(key);
                if (hlp_it != cpu_it->second.end() && r.timestamp >= hlp_it->second) {
                    rb_helper_key_t duration_key = {r.program_id, r.helper_function_id, r.map_id};
                    helper_durations[duration_key].push_back(r.timestamp - hlp_it->second);
                    cpu_it->second.erase(hlp_it);
                }
            }
        }
    }

    if (!program_durations.empty()) {
        // Compute dynamic column widths for program table.
        int id_w = 6;   // "ProgID"
        int name_w = 4; // "Name"
        int cnt_w = 5;  // "Count"
        int num_w = 8;  // "Avg (us)" etc.
        for (auto& [pid, durations] : program_durations) {
            std::sort(durations.begin(), durations.end());
            size_t n = durations.size();
            uint64_t sum = 0;
            for (auto d : durations)
                sum += d;

            char id_buf[16];
            sprintf_s(id_buf, sizeof(id_buf), "%u", pid);
            id_w = (std::max)(id_w, (int)strlen(id_buf));
            auto name_it = program_names.find(pid);
            if (name_it != program_names.end()) {
                name_w = (std::max)(name_w, (int)name_it->second.size());
            }
            cnt_w = (std::max)(cnt_w, (int)std::to_string(n).size());
            num_w = (std::max)(num_w, (int)_format_us(ticks_to_us(sum / n)).size());
            num_w = (std::max)(num_w, (int)_format_us(ticks_to_us(durations[n - 1])).size());
        }

        printf("--- Program Invocation Latency (us) ---\n");
        printf(
            "%-*s %-*s %*s %*s %*s %*s %*s %*s\n",
            id_w,
            "ProgID",
            name_w,
            "Name",
            cnt_w,
            "Count",
            num_w,
            "Avg (us)",
            num_w,
            "P50 (us)",
            num_w,
            "P90 (us)",
            num_w,
            "P99 (us)",
            num_w,
            "Max (us)");

        for (auto& [pid, durations] : program_durations) {
            size_t n = durations.size();
            uint64_t sum = 0;
            for (auto d : durations)
                sum += d;

            auto name_it = program_names.find(pid);
            const char* prog_name = (name_it != program_names.end()) ? name_it->second.c_str() : "";

            printf(
                "%-*u %-*s %*zu %*s %*s %*s %*s %*s\n",
                id_w,
                pid,
                name_w,
                prog_name,
                cnt_w,
                n,
                num_w,
                _format_us(ticks_to_us(sum / n)).c_str(),
                num_w,
                _format_us(ticks_to_us(durations[n * 50 / 100])).c_str(),
                num_w,
                _format_us(ticks_to_us(durations[n * 90 / 100])).c_str(),
                num_w,
                _format_us(ticks_to_us(durations[n * 99 / 100])).c_str(),
                num_w,
                _format_us(ticks_to_us(durations[n - 1])).c_str());
        }
    }

    // Helper latency table (grouped by program).
    if (!helper_durations.empty()) {
        std::map<uint32_t, std::vector<std::tuple<uint16_t, uint16_t, std::vector<uint64_t>*>>> by_program;
        for (auto& [key, durations] : helper_durations) {
            auto& [pid, hid, mid] = key;
            by_program[pid].push_back({hid, mid, &durations});
        }

        for (auto& [pid, helpers] : by_program) {
            auto prog_name_it = program_names.find(pid);
            if (prog_name_it != program_names.end() && !prog_name_it->second.empty()) {
                printf("\n--- Map Helper Summary (Program %u - %s) (us) ---\n", pid, prog_name_it->second.c_str());
            } else {
                printf("\n--- Map Helper Summary (Program %u) (us) ---\n", pid);
            }

            // Compute dynamic column widths for this program's helper table.
            int hlp_w = 6; // "Helper"
            int mid_w = 5; // "MapID"
            int map_w = 8; // "Map Name"
            int cnt_w = 5; // "Count"
            int num_w = 8; // "Avg (us)" etc.
            for (auto& [hid, mid, durations_ptr] : helpers) {
                std::sort(durations_ptr->begin(), durations_ptr->end());
                size_t n = durations_ptr->size();
                uint64_t sum = 0;
                for (auto d : *durations_ptr)
                    sum += d;

                const char* helper_name = _helper_function_name(hid);
                char helper_name_buf[32];
                if (helper_name == nullptr) {
                    sprintf_s(helper_name_buf, sizeof(helper_name_buf), "helper_%u", hid);
                    helper_name = helper_name_buf;
                }
                hlp_w = (std::max)(hlp_w, (int)strlen(helper_name));

                char mid_buf[16];
                sprintf_s(mid_buf, sizeof(mid_buf), "%u", (unsigned)mid);
                mid_w = (std::max)(mid_w, (int)strlen(mid_buf));

                auto map_name_it = map_names.find(mid);
                const char* map_name_str = (map_name_it != map_names.end()) ? map_name_it->second.c_str() : "";
                map_w = (std::max)(map_w, (int)strlen(map_name_str));

                cnt_w = (std::max)(cnt_w, (int)std::to_string(n).size());
                num_w = (std::max)(num_w, (int)_format_us(ticks_to_us(sum / n)).size());
                num_w = (std::max)(num_w, (int)_format_us(ticks_to_us((*durations_ptr)[n - 1])).size());
            }

            printf(
                "%-*s %*s %-*s %*s %*s %*s %*s %*s %*s\n",
                hlp_w,
                "Helper",
                mid_w,
                "MapID",
                map_w,
                "Map Name",
                cnt_w,
                "Count",
                num_w,
                "Avg (us)",
                num_w,
                "P50 (us)",
                num_w,
                "P90 (us)",
                num_w,
                "P99 (us)",
                num_w,
                "Max (us)");

            for (auto& [hid, mid, durations_ptr] : helpers) {
                size_t n = durations_ptr->size();
                uint64_t sum = 0;
                for (auto d : *durations_ptr)
                    sum += d;

                auto map_name_it = map_names.find(mid);
                const char* map_name_str = (map_name_it != map_names.end()) ? map_name_it->second.c_str() : "";

                const char* helper_name = _helper_function_name(hid);
                char helper_name_buf[32];
                if (helper_name == nullptr) {
                    sprintf_s(helper_name_buf, sizeof(helper_name_buf), "helper_%u", hid);
                    helper_name = helper_name_buf;
                }

                printf(
                    "%-*s %*u %-*s %*zu %*s %*s %*s %*s %*s\n",
                    hlp_w,
                    helper_name,
                    mid_w,
                    (unsigned)mid,
                    map_w,
                    map_name_str,
                    cnt_w,
                    n,
                    num_w,
                    _format_us(ticks_to_us(sum / n)).c_str(),
                    num_w,
                    _format_us(ticks_to_us((*durations_ptr)[n * 50 / 100])).c_str(),
                    num_w,
                    _format_us(ticks_to_us((*durations_ptr)[n * 90 / 100])).c_str(),
                    num_w,
                    _format_us(ticks_to_us((*durations_ptr)[n * 99 / 100])).c_str(),
                    num_w,
                    _format_us(ticks_to_us((*durations_ptr)[n - 1])).c_str());
            }
        }
    }

    printf("\nDone.\n");
    return NO_ERROR;
}

unsigned long
handle_ebpf_show_latencytrace(
    LPCWSTR machine, LPWSTR* argv, DWORD current_index, DWORD argc, DWORD flags, LPCVOID data, BOOL* done)
{
    UNREFERENCED_PARAMETER(machine);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(done);

    TAG_TYPE tags[] = {
        {TOKEN_FILE, NS_REQ_ZERO, FALSE},
        {TOKEN_FORMAT, NS_REQ_ZERO, FALSE},
        {TOKEN_INPUT, NS_REQ_ZERO, FALSE},
    };
    const int FILE_INDEX = 0;
    const int FORMAT_INDEX = 1;
    const int INPUT_INDEX = 2;

    unsigned long tag_type[_countof(tags)] = {0};

    unsigned long status =
        PreprocessCommand(nullptr, argv, current_index, argc, tags, _countof(tags), 0, _countof(tags), tag_type);

    if (status != NO_ERROR) {
        return status;
    }

    WCHAR etl_file[MAX_PATH] = {0};
    WCHAR input_file[MAX_PATH] = {0};
    uint32_t format = FORMAT_TABLE;

    for (DWORD i = 0; (status == NO_ERROR) && ((i + current_index) < argc); i++) {
        switch (tag_type[i]) {
        case FILE_INDEX:
            StringCchCopyW(etl_file, MAX_PATH, argv[current_index + i]);
            break;
        case FORMAT_INDEX:
            status = MatchEnumTag(
                nullptr, argv[current_index + i], _countof(_format_enum), _format_enum, (unsigned long*)&format);
            if (status != NO_ERROR) {
                status = ERROR_INVALID_PARAMETER;
            }
            break;
        case INPUT_INDEX:
            StringCchCopyW(input_file, MAX_PATH, argv[current_index + i]);
            break;
        default:
            status = ERROR_INVALID_SYNTAX;
            break;
        }
    }

    if (status != NO_ERROR) {
        return status;
    }

    // If input= is provided, re-parse a saved file (no live drain).
    if (input_file[0] != L'\0') {
        size_t ilen = wcslen(input_file);
        if (ilen >= 4 && _wcsicmp(input_file + ilen - 4, L".etl") == 0) {
            return _show_latencytrace_from_etl(input_file, format);
        }
        if (ilen >= 4 && _wcsicmp(input_file + ilen - 4, L".bin") == 0) {
            return _show_latencytrace_from_bin(input_file, format);
        }
        printf("Error: input= file must end in .etl or .bin.\n");
        return ERROR_INVALID_PARAMETER;
    }

    // If no file provided, query the kernel to determine the active backend.
    if (etl_file[0] == L'\0') {
        uint32_t mode = 0, backend = 0, session_active = 0;
        ebpf_result_t query_result = ebpf_latency_tracking_query_state(&mode, &backend, &session_active);

        if (query_result == EBPF_SUCCESS && backend == EBPF_LATENCY_BACKEND_ETW) {
            // ETW backend: use the default .etl file name.
            return _show_latencytrace_from_etl(DEFAULT_OUTPUT_FILE, format);
        }
        // Ring buffer backend (or no session — drain will report the error).
        return _show_latencytrace_from_ringbuffer(format, nullptr);
    }

    // If file ends in .etl, parse it as an existing ETW trace file.
    size_t len = wcslen(etl_file);
    if (len >= 4 && _wcsicmp(etl_file + len - 4, L".etl") == 0) {
        return _show_latencytrace_from_etl(etl_file, format);
    }

    // Otherwise, treat as output file path for ring buffer drain.
    char output_path_narrow[MAX_PATH] = {0};
    WideCharToMultiByte(CP_ACP, 0, etl_file, -1, output_path_narrow, MAX_PATH, nullptr, nullptr);
    return _show_latencytrace_from_ringbuffer(format, output_path_narrow);
}

// Process an .etl file and display latency report.
static unsigned long
_show_latencytrace_from_etl(_In_z_ LPCWSTR etl_file, uint32_t format)
{
    DWORD file_attrs = GetFileAttributesW(etl_file);
    if (file_attrs == INVALID_FILE_ATTRIBUTES) {
        printf("Error: cannot open file '%ls' (error=%lu).\n", etl_file, GetLastError());
        return ERROR_SUPPRESS_OUTPUT;
    }

    // Set up ETW consumer context.
    latency_trace_context_t ctx = {};
    ctx.csv_format = (format == FORMAT_CSV);

    EVENT_TRACE_LOGFILEW trace_logfile = {};
    trace_logfile.LogFileName = const_cast<LPWSTR>(etl_file);
    trace_logfile.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD;
    trace_logfile.EventRecordCallback = _etl_event_record_callback;
    trace_logfile.Context = &ctx;

    TRACEHANDLE trace_handle = OpenTraceW(&trace_logfile);
    if (trace_handle == INVALID_PROCESSTRACE_HANDLE) {
        printf("Error: OpenTrace failed for '%ls' (error=%lu).\n", etl_file, GetLastError());
        return ERROR_SUPPRESS_OUTPUT;
    }

    // Save timer resolution for duration computation.
    ctx.timer_resolution = trace_logfile.LogfileHeader.PerfFreq.QuadPart;

    // Print CSV header if in CSV mode.
    if (ctx.csv_format) {
        printf("EventType,ProgramId,ProgramName,HelperFunctionId,MapName,"
               "ProcessId,ThreadId,StartTime,EndTime,Duration_us,CpuId,Irql,CorrelationId\n");
    }

    // Process all events in the file.
    DWORD status = ProcessTrace(&trace_handle, 1, nullptr, nullptr);
    CloseTrace(trace_handle);

    if (status != ERROR_SUCCESS && status != ERROR_CANCELLED) {
        printf("Error: ProcessTrace failed (error=%lu).\n", status);
        return ERROR_SUPPRESS_OUTPUT;
    }

    // For CSV mode, events were printed as they arrived; just emit the summary count.
    if (ctx.csv_format) {
        fprintf(stderr, "Exported %s records to CSV.\n", _format_number(ctx.total_events).c_str());
        return NO_ERROR;
    }

    // ---- Table mode: print the summary report ----

    // Compute trace duration.
    double trace_duration_sec = 0.0;
    if (ctx.timer_resolution > 0 && ctx.last_timestamp > ctx.first_timestamp) {
        trace_duration_sec = (double)(ctx.last_timestamp - ctx.first_timestamp) / (double)ctx.timer_resolution;
    }

    printf("\neBPF Latency Report (%ls):\n", etl_file);
    printf("  Duration: %.1f seconds\n", trace_duration_sec);
    printf("  Total events: %s\n\n", _format_number(ctx.total_events).c_str());

    // Program Invocation Summary.
    if (!ctx.program_durations.empty()) {
        // Compute dynamic column widths.
        int id_w = 10;   // strlen("Program ID")
        int name_w = 12; // strlen("Program Name")
        int inv_w = 11;  // strlen("Invocations")
        int num_w = 8;   // strlen("Avg (us)") etc.
        for (auto& [prog_id, durations] : ctx.program_durations) {
            uint64_t avg, p50, p95, p99, max_val;
            _compute_stats(durations, &avg, &p50, &p95, &p99, &max_val);
            char id_buf[16];
            sprintf_s(id_buf, sizeof(id_buf), "%u", prog_id);
            id_w = (std::max)(id_w, (int)strlen(id_buf));
            auto name_it = ctx.program_names.find(prog_id);
            if (name_it != ctx.program_names.end()) {
                name_w = (std::max)(name_w, (int)name_it->second.size());
            }
            inv_w = (std::max)(inv_w, (int)_format_number(durations.size()).size());
            num_w = (std::max)(num_w, (int)_format_number(avg).size());
            num_w = (std::max)(num_w, (int)_format_number(p50).size());
            num_w = (std::max)(num_w, (int)_format_number(p95).size());
            num_w = (std::max)(num_w, (int)_format_number(p99).size());
            num_w = (std::max)(num_w, (int)_format_number(max_val).size());
        }

        printf("Program Invocation Summary:\n");
        printf(
            "  %-*s %-*s %-*s %-*s %-*s %-*s %-*s %-*s\n",
            id_w,
            "Program ID",
            name_w,
            "Program Name",
            inv_w,
            "Invocations",
            num_w,
            "Avg (us)",
            num_w,
            "P50 (us)",
            num_w,
            "P95 (us)",
            num_w,
            "P99 (us)",
            num_w,
            "Max (us)");
        printf(
            "  %-*s %-*s %-*s %-*s %-*s %-*s %-*s %-*s\n",
            id_w,
            std::string(id_w, '-').c_str(),
            name_w,
            std::string(name_w, '-').c_str(),
            inv_w,
            std::string(inv_w, '-').c_str(),
            num_w,
            std::string(num_w, '-').c_str(),
            num_w,
            std::string(num_w, '-').c_str(),
            num_w,
            std::string(num_w, '-').c_str(),
            num_w,
            std::string(num_w, '-').c_str(),
            num_w,
            std::string(num_w, '-').c_str());

        for (auto& [prog_id, durations] : ctx.program_durations) {
            uint64_t avg, p50, p95, p99, max_val;
            _compute_stats(durations, &avg, &p50, &p95, &p99, &max_val);

            auto name_it = ctx.program_names.find(prog_id);
            const char* prog_name = (name_it != ctx.program_names.end()) ? name_it->second.c_str() : "";

            printf(
                "  %-*u %-*s %-*s %-*s %-*s %-*s %-*s %-*s\n",
                id_w,
                prog_id,
                name_w,
                prog_name,
                inv_w,
                _format_number(durations.size()).c_str(),
                num_w,
                _format_number(avg).c_str(),
                num_w,
                _format_number(p50).c_str(),
                num_w,
                _format_number(p95).c_str(),
                num_w,
                _format_number(p99).c_str(),
                num_w,
                _format_number(max_val).c_str());
        }
        printf("\n");
    }

    // Map Helper Summary (grouped by program).
    if (!ctx.helper_durations.empty()) {
        // Group by program_id.
        std::map<uint32_t, std::vector<std::tuple<uint32_t, std::string, std::vector<uint64_t>*>>> by_program;
        for (auto& [key, durations] : ctx.helper_durations) {
            auto& [pid, hid, mname] = key;
            by_program[pid].push_back({hid, mname, &durations});
        }

        for (auto& [prog_id, helpers] : by_program) {
            auto name_it = ctx.program_names.find(prog_id);
            if (name_it != ctx.program_names.end() && !name_it->second.empty()) {
                printf("Map Helper Summary (Program %u - %s):\n", prog_id, name_it->second.c_str());
            } else {
                printf("Map Helper Summary (Program %u):\n", prog_id);
            }

            // Compute dynamic column widths for this program's helper table.
            int hlp_w = 6;   // strlen("Helper")
            int map_w = 8;   // strlen("Map Name")
            int calls_w = 5; // strlen("Calls")
            int num_w = 8;   // strlen("Avg (us)") etc.
            for (auto& [helper_id, map_name_str, durations_ptr] : helpers) {
                uint64_t avg, p50, p95, p99, max_val;
                _compute_stats(*durations_ptr, &avg, &p50, &p95, &p99, &max_val);

                const char* helper_name = _helper_function_name(helper_id);
                char helper_name_buf[32];
                if (helper_name == nullptr) {
                    sprintf_s(helper_name_buf, sizeof(helper_name_buf), "helper_%u", helper_id);
                    helper_name = helper_name_buf;
                }
                hlp_w = (std::max)(hlp_w, (int)strlen(helper_name));

                const char* map_display = map_name_str.empty() ? "(unknown)" : map_name_str.c_str();
                map_w = (std::max)(map_w, (int)strlen(map_display));

                calls_w = (std::max)(calls_w, (int)_format_number(durations_ptr->size()).size());
                num_w = (std::max)(num_w, (int)_format_number(avg).size());
                num_w = (std::max)(num_w, (int)_format_number(p50).size());
                num_w = (std::max)(num_w, (int)_format_number(p95).size());
                num_w = (std::max)(num_w, (int)_format_number(p99).size());
                num_w = (std::max)(num_w, (int)_format_number(max_val).size());
            }

            printf(
                "  %-*s %-*s %-*s %-*s %-*s %-*s %-*s %-*s\n",
                hlp_w,
                "Helper",
                map_w,
                "Map Name",
                calls_w,
                "Calls",
                num_w,
                "Avg (us)",
                num_w,
                "P50 (us)",
                num_w,
                "P95 (us)",
                num_w,
                "P99 (us)",
                num_w,
                "Max (us)");
            printf(
                "  %-*s %-*s %-*s %-*s %-*s %-*s %-*s %-*s\n",
                hlp_w,
                std::string(hlp_w, '-').c_str(),
                map_w,
                std::string(map_w, '-').c_str(),
                calls_w,
                std::string(calls_w, '-').c_str(),
                num_w,
                std::string(num_w, '-').c_str(),
                num_w,
                std::string(num_w, '-').c_str(),
                num_w,
                std::string(num_w, '-').c_str(),
                num_w,
                std::string(num_w, '-').c_str(),
                num_w,
                std::string(num_w, '-').c_str());

            for (auto& [helper_id, map_name_str, durations_ptr] : helpers) {
                uint64_t avg, p50, p95, p99, max_val;
                _compute_stats(*durations_ptr, &avg, &p50, &p95, &p99, &max_val);

                const char* helper_name = _helper_function_name(helper_id);
                char helper_name_buf[32];
                if (helper_name == nullptr) {
                    sprintf_s(helper_name_buf, sizeof(helper_name_buf), "helper_%u", helper_id);
                    helper_name = helper_name_buf;
                }

                const char* map_display = map_name_str.empty() ? "(unknown)" : map_name_str.c_str();

                printf(
                    "  %-*s %-*s %-*s %-*s %-*s %-*s %-*s %-*s\n",
                    hlp_w,
                    helper_name,
                    map_w,
                    map_display,
                    calls_w,
                    _format_number(durations_ptr->size()).c_str(),
                    num_w,
                    _format_number(avg).c_str(),
                    num_w,
                    _format_number(p50).c_str(),
                    num_w,
                    _format_number(p95).c_str(),
                    num_w,
                    _format_number(p99).c_str(),
                    num_w,
                    _format_number(max_val).c_str());
            }
            printf("\n");
        }
    }

    // Extension End-to-End Latency Summary.
    if (!ctx.ext_durations.empty()) {
        // Compute dynamic column widths.
        int id_w = 10;   // strlen("Program ID")
        int name_w = 12; // strlen("Program Name")
        int inv_w = 11;  // strlen("Invocations")
        int num_w = 8;   // strlen("Avg (us)") etc.
        for (auto& [prog_id, durations] : ctx.ext_durations) {
            uint64_t avg, p50, p95, p99, max_val;
            _compute_stats(durations, &avg, &p50, &p95, &p99, &max_val);
            char id_buf[16];
            sprintf_s(id_buf, sizeof(id_buf), "%u", prog_id);
            id_w = (std::max)(id_w, (int)strlen(id_buf));
            auto name_it = ctx.program_names.find(prog_id);
            if (name_it != ctx.program_names.end()) {
                name_w = (std::max)(name_w, (int)name_it->second.size());
            }
            inv_w = (std::max)(inv_w, (int)_format_number(durations.size()).size());
            num_w = (std::max)(num_w, (int)_format_number(avg).size());
            num_w = (std::max)(num_w, (int)_format_number(p50).size());
            num_w = (std::max)(num_w, (int)_format_number(p95).size());
            num_w = (std::max)(num_w, (int)_format_number(p99).size());
            num_w = (std::max)(num_w, (int)_format_number(max_val).size());
        }

        printf("Extension Invoke Latency Summary:\n");
        printf(
            "  %-*s %-*s %-*s %-*s %-*s %-*s %-*s %-*s\n",
            id_w,
            "Program ID",
            name_w,
            "Program Name",
            inv_w,
            "Invocations",
            num_w,
            "Avg (us)",
            num_w,
            "P50 (us)",
            num_w,
            "P95 (us)",
            num_w,
            "P99 (us)",
            num_w,
            "Max (us)");
        printf(
            "  %-*s %-*s %-*s %-*s %-*s %-*s %-*s %-*s\n",
            id_w,
            std::string(id_w, '-').c_str(),
            name_w,
            std::string(name_w, '-').c_str(),
            inv_w,
            std::string(inv_w, '-').c_str(),
            num_w,
            std::string(num_w, '-').c_str(),
            num_w,
            std::string(num_w, '-').c_str(),
            num_w,
            std::string(num_w, '-').c_str(),
            num_w,
            std::string(num_w, '-').c_str(),
            num_w,
            std::string(num_w, '-').c_str());

        for (auto& [prog_id, durations] : ctx.ext_durations) {
            uint64_t avg, p50, p95, p99, max_val;
            _compute_stats(durations, &avg, &p50, &p95, &p99, &max_val);

            auto name_it = ctx.program_names.find(prog_id);
            const char* prog_name = (name_it != ctx.program_names.end()) ? name_it->second.c_str() : "";

            printf(
                "  %-*u %-*s %-*s %-*s %-*s %-*s %-*s %-*s\n",
                id_w,
                prog_id,
                name_w,
                prog_name,
                inv_w,
                _format_number(durations.size()).c_str(),
                num_w,
                _format_number(avg).c_str(),
                num_w,
                _format_number(p50).c_str(),
                num_w,
                _format_number(p95).c_str(),
                num_w,
                _format_number(p99).c_str(),
                num_w,
                _format_number(max_val).c_str());
        }
        printf("\n");
    }

    if (ctx.total_events == 0) {
        printf("  No latency events found in the trace file.\n");
        printf("  Ensure latency tracking was enabled before capturing:\n");
        printf("    netsh ebpf set latency mode=all backend=etw file=<path.etl>\n\n");
    }

    return NO_ERROR;
}
