// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "ebpf_api.h"
#include "latency.h"
#include "tokens.h"
#include "utilities.h"

#include <algorithm>
#include <map>
#include <string>
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
    };
    const int MODE_INDEX = 0;

    unsigned long tag_type[_countof(tags)] = {0};

    unsigned long status =
        PreprocessCommand(nullptr, argv, current_index, argc, tags, _countof(tags), 0, _countof(tags), tag_type);

    if (status != NO_ERROR) {
        return status;
    }

    uint32_t mode = LATENCY_MODE_OFF;
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
        result = ebpf_latency_tracking_disable();
        if (result == EBPF_SUCCESS) {
            printf("Latency tracking disabled.\n");
        }
    } else {
        result = ebpf_latency_tracking_enable(mode);
        if (result == EBPF_SUCCESS) {
            if (mode == LATENCY_MODE_PROGRAM) {
                printf("Latency tracking enabled (mode=program).\n");
            } else {
                printf("Latency tracking enabled (mode=program+helpers).\n");
            }
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
    printf("  Use 'netsh ebpf set latency mode=off|program|all' to control latency tracking.\n");
    printf("  Use 'tracelog' or 'wpr' to capture ETW events with keyword 0x800.\n");
    printf("  Use Windows Performance Analyzer (WPA) to analyze .etl files.\n\n");
    printf("  ETW Provider: ebpf_tracelog_provider\n");
    printf("  Latency Keyword: 0x800\n");
    printf("  Events: EbpfProgramLatency, EbpfMapHelperLatency\n\n");

    return NO_ERROR;
}

// ETW trace session name for latency tracing.
static const WCHAR _ebpf_latency_session_name[] = L"EbpfLatencyTrace";

// EbpfForWindowsProvider {394f321c-5cf4-404c-aa34-4df1428a7f9c}
static const GUID _ebpf_core_provider_guid = {
    0x394f321c, 0x5cf4, 0x404c, {0xaa, 0x34, 0x4d, 0xf1, 0x42, 0x8a, 0x7f, 0x9c}};

// NetEbpfExtProvider {f2f2ca01-ad02-4a07-9e90-95a2334f3692}
static const GUID _net_ebpf_ext_provider_guid = {
    0xf2f2ca01, 0xad02, 0x4a07, {0x9e, 0x90, 0x95, 0xa2, 0x33, 0x4f, 0x36, 0x92}};

// Latency keyword as defined in the design doc.
#define EBPF_TRACELOG_KEYWORD_LATENCY 0x800

#define TOKEN_FILE L"file"
#define TOKEN_BUFFERSIZE L"buffersize"

// Default ETW session parameters.
#define DEFAULT_BUFFER_SIZE_KB 256
#define DEFAULT_MIN_BUFFERS 64
#define DEFAULT_MAX_BUFFERS 256
#define DEFAULT_FLUSH_TIMER_SEC 1
#define DEFAULT_OUTPUT_FILE L"ebpf_latency.etl"

unsigned long
handle_ebpf_start_latencytrace(
    LPCWSTR machine, LPWSTR* argv, DWORD current_index, DWORD argc, DWORD flags, LPCVOID data, BOOL* done)
{
    UNREFERENCED_PARAMETER(machine);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(done);

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

    // Allocate EVENT_TRACE_PROPERTIES with space for session name and log file name.
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

    // Copy the log file name into the properties buffer.
    StringCchCopyW((LPWSTR)((BYTE*)properties + properties->LogFileNameOffset), MAX_PATH, output_file);

    TRACEHANDLE session_handle = 0;
    status = StartTraceW(&session_handle, _ebpf_latency_session_name, properties);
    if (status != ERROR_SUCCESS) {
        if (status == ERROR_ALREADY_EXISTS) {
            printf("Error: ETW trace session '%ls' is already running.\n", _ebpf_latency_session_name);
            printf("  Use 'netsh ebpf stop latencytrace' to stop it first.\n");
        } else {
            printf("Error: StartTrace failed (error=%lu).\n", status);
        }
        free(properties);
        return ERROR_SUPPRESS_OUTPUT;
    }

    // Enable the ebpfcore provider with the latency keyword.
    ENABLE_TRACE_PARAMETERS enable_params = {0};
    enable_params.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
    status = EnableTraceEx2(
        session_handle,
        &_ebpf_core_provider_guid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE,
        EBPF_TRACELOG_KEYWORD_LATENCY,
        0, // MatchAllKeyword
        0, // Timeout
        &enable_params);

    if (status != ERROR_SUCCESS) {
        printf("Warning: failed to enable EbpfForWindowsProvider (error=%lu).\n", status);
        // Continue - the session is started, user can enable providers manually.
    }

    // Enable the netebpfext provider with the latency keyword.
    status = EnableTraceEx2(
        session_handle,
        &_net_ebpf_ext_provider_guid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE,
        EBPF_TRACELOG_KEYWORD_LATENCY,
        0, // MatchAllKeyword
        0, // Timeout
        &enable_params);

    if (status != ERROR_SUCCESS) {
        printf("Warning: failed to enable NetEbpfExtProvider (error=%lu).\n", status);
        // Continue - the session is started with the core provider.
    }

    printf("Started ETW trace session '%ls'.\n", _ebpf_latency_session_name);
    printf("  Provider: {394f321c-5cf4-404c-aa34-4df1428a7f9c} (EbpfForWindows)\n");
    printf("  Provider: {f2f2ca01-ad02-4a07-9e90-95a2334f3692} (NetEbpfExt)\n");
    printf("  Keywords: 0x%x, Level: Verbose\n", EBPF_TRACELOG_KEYWORD_LATENCY);
    printf("  Output:   %ls\n", output_file);
    printf("  Buffers:  %lu KB x %d-%d\n", buffer_size_kb, DEFAULT_MIN_BUFFERS, DEFAULT_MAX_BUFFERS);

    free(properties);
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

    // Allocate EVENT_TRACE_PROPERTIES with space for session name and log file name.
    ULONG properties_size =
        sizeof(EVENT_TRACE_PROPERTIES) + sizeof(_ebpf_latency_session_name) + (MAX_PATH * sizeof(WCHAR));
    EVENT_TRACE_PROPERTIES* properties = (EVENT_TRACE_PROPERTIES*)calloc(1, properties_size);
    if (properties == nullptr) {
        printf("Error: out of memory.\n");
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    properties->Wnode.BufferSize = properties_size;
    properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    properties->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(_ebpf_latency_session_name);

    unsigned long status = ControlTraceW(0, _ebpf_latency_session_name, properties, EVENT_TRACE_CONTROL_STOP);

    if (status != ERROR_SUCCESS) {
        if (status == ERROR_WMI_INSTANCE_NOT_FOUND) {
            printf("Error: ETW trace session '%ls' is not running.\n", _ebpf_latency_session_name);
        } else {
            printf("Error: ControlTrace(STOP) failed (error=%lu).\n", status);
        }
        free(properties);
        return ERROR_SUPPRESS_OUTPUT;
    }

    LPCWSTR log_file_name = (LPCWSTR)((BYTE*)properties + properties->LogFileNameOffset);
    printf("Stopped ETW trace session '%ls'.\n", _ebpf_latency_session_name);
    printf("  Events collected: %lu\n", properties->EventsLost == 0 ? properties->NumberOfBuffers : 0);
    printf("  Events lost:      %lu\n", properties->EventsLost);
    printf("  Buffers used:     %lu\n", properties->NumberOfBuffers);
    if (log_file_name[0] != L'\0') {
        printf("  Saved to:         %ls\n", log_file_name);
    }

    free(properties);
    return NO_ERROR;
}

// ============================================================================
// show latencytrace — ETL file parser and latency report generator
// ============================================================================

// Conversion factor: 100-ns units to nanoseconds.
#define FILETIME_UNITS_TO_NS 100

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
    case 16:
        return "map_push_elem";
    case 17:
        return "map_pop_elem";
    case 18:
        return "map_peek_elem";
    default:
        return nullptr;
    }
}

// Context passed through the ETW consumer callback.
typedef struct _latency_trace_context
{
    // program_id -> vector of durations (100-ns units).
    std::map<uint32_t, std::vector<uint64_t>> program_durations;

    // (program_id, helper_id) -> vector of durations (100-ns units).
    std::map<std::pair<uint32_t, uint32_t>, std::vector<uint64_t>> helper_durations;

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

// Print a single event as a CSV row.
static void
_print_csv_event(
    _In_z_ const char* event_type,
    uint32_t program_id,
    uint32_t helper_function_id,
    uint32_t process_id,
    uint32_t thread_id,
    uint64_t start_time,
    uint64_t end_time,
    uint64_t duration,
    uint8_t cpu_id,
    uint8_t irql)
{
    printf(
        "%s,%u,%u,%u,%u,%llu,%llu,%llu,%u,%u\n",
        event_type,
        program_id,
        helper_function_id,
        process_id,
        thread_id,
        (unsigned long long)start_time,
        (unsigned long long)end_time,
        (unsigned long long)(duration * FILETIME_UNITS_TO_NS),
        (unsigned)cpu_id,
        (unsigned)irql);
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
        uint64_t duration = _get_uint64_property(event_record, L"Duration");

        if (ctx->csv_format) {
            uint32_t helper_id = _get_uint32_property(event_record, L"HelperFunctionId");
            uint32_t process_id = _get_uint32_property(event_record, L"ProcessId");
            uint32_t thread_id = _get_uint32_property(event_record, L"ThreadId");
            uint64_t start_time = _get_uint64_property(event_record, L"StartTime");
            uint64_t end_time = _get_uint64_property(event_record, L"EndTime");
            uint8_t cpu_id = _get_uint8_property(event_record, L"CpuId");
            uint8_t irql = _get_uint8_property(event_record, L"Irql");
            _print_csv_event(
                "ProgramInvoke",
                program_id,
                helper_id,
                process_id,
                thread_id,
                start_time,
                end_time,
                duration,
                cpu_id,
                irql);
        } else {
            ctx->program_durations[program_id].push_back(duration);
        }
        ctx->total_events++;
    } else if (is_core && wcscmp(event_name, L"EbpfMapHelperLatency") == 0) {
        uint32_t program_id = _get_uint32_property(event_record, L"ProgramId");
        uint32_t helper_id = _get_uint32_property(event_record, L"HelperFunctionId");
        uint64_t duration = _get_uint64_property(event_record, L"Duration");

        if (ctx->csv_format) {
            uint32_t process_id = _get_uint32_property(event_record, L"ProcessId");
            uint32_t thread_id = _get_uint32_property(event_record, L"ThreadId");
            uint64_t start_time = _get_uint64_property(event_record, L"StartTime");
            uint64_t end_time = _get_uint64_property(event_record, L"EndTime");
            uint8_t cpu_id = _get_uint8_property(event_record, L"CpuId");
            uint8_t irql = _get_uint8_property(event_record, L"Irql");
            _print_csv_event(
                "MapHelper",
                program_id,
                helper_id,
                process_id,
                thread_id,
                start_time,
                end_time,
                duration,
                cpu_id,
                irql);
        } else {
            ctx->helper_durations[{program_id, helper_id}].push_back(duration);
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
                "ExtInvoke", program_id, hook_type, process_id, thread_id, start_time, end_time, duration, cpu_id, 0);
        } else {
            ctx->ext_durations[program_id].push_back(duration);
        }
        ctx->total_events++;
    }
}

// Compute statistics from a sorted vector of durations (100-ns units).
// Returns results in nanoseconds.
static void
_compute_stats(
    _Inout_ std::vector<uint64_t>& durations,
    _Out_ uint64_t* avg_ns,
    _Out_ uint64_t* p50_ns,
    _Out_ uint64_t* p95_ns,
    _Out_ uint64_t* p99_ns,
    _Out_ uint64_t* max_ns)
{
    std::sort(durations.begin(), durations.end());
    size_t n = durations.size();
    if (n == 0) {
        *avg_ns = *p50_ns = *p95_ns = *p99_ns = *max_ns = 0;
        return;
    }

    uint64_t sum = 0;
    for (auto d : durations) {
        sum += d;
    }
    *avg_ns = (sum / n) * FILETIME_UNITS_TO_NS;
    *p50_ns = durations[n * 50 / 100] * FILETIME_UNITS_TO_NS;
    *p95_ns = durations[n * 95 / 100] * FILETIME_UNITS_TO_NS;
    *p99_ns = durations[n * 99 / 100] * FILETIME_UNITS_TO_NS;
    *max_ns = durations[n - 1] * FILETIME_UNITS_TO_NS;
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

#define TOKEN_FORMAT L"format"

typedef enum
{
    FORMAT_TABLE = 0,
    FORMAT_CSV = 1,
} FORMAT_VALUE;

static TOKEN_VALUE _format_enum[] = {
    {L"table", FORMAT_TABLE},
    {L"csv", FORMAT_CSV},
};

unsigned long
handle_ebpf_show_latencytrace(
    LPCWSTR machine, LPWSTR* argv, DWORD current_index, DWORD argc, DWORD flags, LPCVOID data, BOOL* done)
{
    UNREFERENCED_PARAMETER(machine);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(done);

    TAG_TYPE tags[] = {
        {TOKEN_FILE, NS_REQ_PRESENT, FALSE},
        {TOKEN_FORMAT, NS_REQ_ZERO, FALSE},
    };
    const int FILE_INDEX = 0;
    const int FORMAT_INDEX = 1;

    unsigned long tag_type[_countof(tags)] = {0};

    unsigned long status =
        PreprocessCommand(nullptr, argv, current_index, argc, tags, _countof(tags), 0, _countof(tags), tag_type);

    if (status != NO_ERROR) {
        return status;
    }

    WCHAR etl_file[MAX_PATH] = {0};
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
        default:
            status = ERROR_INVALID_SYNTAX;
            break;
        }
    }

    if (status != NO_ERROR) {
        return status;
    }

    if (etl_file[0] == L'\0') {
        printf("Error: file parameter is required.\n");
        return ERROR_INVALID_PARAMETER;
    }

    // Verify the file exists.
    DWORD file_attrs = GetFileAttributesW(etl_file);
    if (file_attrs == INVALID_FILE_ATTRIBUTES) {
        printf("Error: cannot open file '%ls' (error=%lu).\n", etl_file, GetLastError());
        return ERROR_SUPPRESS_OUTPUT;
    }

    // Set up ETW consumer context.
    latency_trace_context_t ctx = {};
    ctx.csv_format = (format == FORMAT_CSV);

    EVENT_TRACE_LOGFILEW trace_logfile = {};
    trace_logfile.LogFileName = etl_file;
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
        printf("EventType,ProgramId,HelperFunctionId,ProcessId,ThreadId,"
               "StartTime,EndTime,Duration_ns,CpuId,Irql\n");
    }

    // Process all events in the file.
    status = ProcessTrace(&trace_handle, 1, nullptr, nullptr);
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
        printf("Program Invocation Summary:\n");
        printf(
            "  %-12s %-13s %-11s %-11s %-11s %-11s %-11s\n",
            "Program ID",
            "Invocations",
            "Avg (ns)",
            "P50 (ns)",
            "P95 (ns)",
            "P99 (ns)",
            "Max (ns)");
        printf(
            "  %-12s %-13s %-11s %-11s %-11s %-11s %-11s\n",
            "----------",
            "-----------",
            "--------",
            "--------",
            "--------",
            "--------",
            "--------");

        for (auto& [prog_id, durations] : ctx.program_durations) {
            uint64_t avg, p50, p95, p99, max_val;
            _compute_stats(durations, &avg, &p50, &p95, &p99, &max_val);
            printf(
                "  %-12u %-13s %-11s %-11s %-11s %-11s %-11s\n",
                prog_id,
                _format_number(durations.size()).c_str(),
                _format_number(avg).c_str(),
                _format_number(p50).c_str(),
                _format_number(p95).c_str(),
                _format_number(p99).c_str(),
                _format_number(max_val).c_str());
        }
        printf("\n");
    }

    // Map Helper Summary (grouped by program).
    if (!ctx.helper_durations.empty()) {
        // Group by program_id.
        std::map<uint32_t, std::vector<std::pair<uint32_t, std::vector<uint64_t>*>>> by_program;
        for (auto& [key, durations] : ctx.helper_durations) {
            by_program[key.first].push_back({key.second, &durations});
        }

        for (auto& [prog_id, helpers] : by_program) {
            printf("Map Helper Summary (Program %u):\n", prog_id);
            printf(
                "  %-24s %-11s %-11s %-11s %-11s %-11s %-11s\n",
                "Helper",
                "Calls",
                "Avg (ns)",
                "P50 (ns)",
                "P95 (ns)",
                "P99 (ns)",
                "Max (ns)");
            printf(
                "  %-24s %-11s %-11s %-11s %-11s %-11s %-11s\n",
                "--------------------",
                "---------",
                "--------",
                "--------",
                "--------",
                "--------",
                "--------");

            for (auto& [helper_id, durations_ptr] : helpers) {
                uint64_t avg, p50, p95, p99, max_val;
                _compute_stats(*durations_ptr, &avg, &p50, &p95, &p99, &max_val);

                const char* name = _helper_function_name(helper_id);
                char name_buf[32];
                if (name == nullptr) {
                    sprintf_s(name_buf, sizeof(name_buf), "helper_%u", helper_id);
                    name = name_buf;
                }

                printf(
                    "  %-24s %-11s %-11s %-11s %-11s %-11s %-11s\n",
                    name,
                    _format_number(durations_ptr->size()).c_str(),
                    _format_number(avg).c_str(),
                    _format_number(p50).c_str(),
                    _format_number(p95).c_str(),
                    _format_number(p99).c_str(),
                    _format_number(max_val).c_str());
            }
            printf("\n");
        }
    }

    // Extension End-to-End Latency Summary.
    if (!ctx.ext_durations.empty()) {
        printf("Extension Invoke Latency Summary:\n");
        printf(
            "  %-12s %-13s %-11s %-11s %-11s %-11s %-11s\n",
            "Program ID",
            "Invocations",
            "Avg (ns)",
            "P50 (ns)",
            "P95 (ns)",
            "P99 (ns)",
            "Max (ns)");
        printf(
            "  %-12s %-13s %-11s %-11s %-11s %-11s %-11s\n",
            "----------",
            "-----------",
            "--------",
            "--------",
            "--------",
            "--------",
            "--------");

        for (auto& [prog_id, durations] : ctx.ext_durations) {
            uint64_t avg, p50, p95, p99, max_val;
            _compute_stats(durations, &avg, &p50, &p95, &p99, &max_val);
            printf(
                "  %-12u %-13s %-11s %-11s %-11s %-11s %-11s\n",
                prog_id,
                _format_number(durations.size()).c_str(),
                _format_number(avg).c_str(),
                _format_number(p50).c_str(),
                _format_number(p95).c_str(),
                _format_number(p99).c_str(),
                _format_number(max_val).c_str());
        }
        printf("\n");
    }

    if (ctx.total_events == 0) {
        printf("  No latency events found in the trace file.\n");
        printf("  Ensure latency tracking was enabled before capturing:\n");
        printf("    netsh ebpf set latency mode=program\n");
        printf("    netsh ebpf start latencytrace file=<path.etl>\n\n");
    }

    return NO_ERROR;
}
