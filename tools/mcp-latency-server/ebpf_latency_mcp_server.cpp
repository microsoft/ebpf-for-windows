// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// ============================================================================
// ebpf_latency_mcp_server.cpp
//
// An MCP (Model Context Protocol) server that ingests eBPF latency ETL files
// and exposes structured query tools via JSON-RPC 2.0 over stdin/stdout.
//
// Build:
//   cl /EHsc /std:c++17 /O2 ebpf_latency_mcp_server.cpp /link tdh.lib advapi32.lib
//
// Usage:
//   The server communicates via newline-delimited JSON-RPC on stdin/stdout.
//   It is designed to be launched as a child process by an MCP client (e.g.,
//   VS Code Copilot). The client sends JSON-RPC requests on stdin; the server
//   writes JSON-RPC responses on stdout.
//
// MCP Tools Exposed:
//   - load_etl:              Ingest an ETL file and index all latency events.
//   - get_summary:           Overall trace summary (like netsh show latencytrace).
//   - get_program_summary:   Per-program statistics with percentiles (one or all).
//   - get_helper_summary:    Per-helper statistics for a given program.
//   - get_map_summary:       Per-map aggregate statistics for a given program.
//   - get_percentile_instance: Find the specific invocation at a given percentile,
//                             optionally including correlated helpers and gap analysis.
//   - get_percentile_comparison: Compare multiple percentiles in a single call.
//   - get_program_events:    List all invocation events for a program (paginated).
//   - get_correlated_map_helpers: Given a correlation_id or time window, find
//                             all map helper calls that occurred within it.
//   - get_invocation_timeline: Timeline of an invocation with gap detection.
//   - list_programs:         List all program IDs and names in the loaded trace.
//   - unload:                Release a previously loaded trace from memory.
// ============================================================================

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <evntcons.h>
#include <evntrace.h>
#include <fcntl.h>
#include <guiddef.h>
#include <io.h>
#include <iostream>
#include <map>
#include <mutex>
#include <numeric>
#include <optional>
#include <sstream>
#include <string>
#include <tdh.h>
#include <tuple>
#include <unordered_map>
#include <vector>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

// ============================================================================
// Minimal JSON helpers (no external dependency)
// ============================================================================

// A simple JSON value type that supports null, bool, int64, double, string,
// array, and object. Enough for JSON-RPC messages.
class JsonValue
{
  public:
    enum Type
    {
        Null,
        Bool,
        Int,
        Double,
        String,
        Array,
        Object
    };

    Type type = Null;
    bool bool_val = false;
    int64_t int_val = 0;
    double double_val = 0.0;
    std::string string_val;
    std::vector<JsonValue> array_val;
    std::vector<std::pair<std::string, JsonValue>> object_val;

    JsonValue() = default;
    explicit JsonValue(std::nullptr_t) : type(Null) {}
    explicit JsonValue(bool v) : type(Bool), bool_val(v) {}
    explicit JsonValue(int v) : type(Int), int_val(v) {}
    explicit JsonValue(int64_t v) : type(Int), int_val(v) {}
    explicit JsonValue(uint64_t v) : type(Int), int_val(static_cast<int64_t>(v)) {}
    explicit JsonValue(uint32_t v) : type(Int), int_val(static_cast<int64_t>(v)) {}
    explicit JsonValue(double v) : type(Double), double_val(v) {}
    explicit JsonValue(const std::string& v) : type(String), string_val(v) {}
    explicit JsonValue(const char* v) : type(String), string_val(v ? v : "") {}

    static JsonValue
    make_array()
    {
        JsonValue v;
        v.type = Array;
        return v;
    }
    static JsonValue
    make_object()
    {
        JsonValue v;
        v.type = Object;
        return v;
    }

    void
    push_back(const JsonValue& v)
    {
        type = Array;
        array_val.push_back(v);
    }

    void
    set(const std::string& key, const JsonValue& v)
    {
        type = Object;
        for (auto& kv : object_val) {
            if (kv.first == key) {
                kv.second = v;
                return;
            }
        }
        object_val.push_back({key, v});
    }

    const JsonValue*
    get(const std::string& key) const
    {
        if (type != Object)
            return nullptr;
        for (auto& kv : object_val) {
            if (kv.first == key)
                return &kv.second;
        }
        return nullptr;
    }

    std::string
    get_string(const std::string& key, const std::string& def = "") const
    {
        auto* v = get(key);
        return (v && v->type == String) ? v->string_val : def;
    }

    int64_t
    get_int(const std::string& key, int64_t def = 0) const
    {
        auto* v = get(key);
        return (v && v->type == Int) ? v->int_val : def;
    }

    double
    get_double(const std::string& key, double def = 0.0) const
    {
        auto* v = get(key);
        if (v && v->type == Double)
            return v->double_val;
        if (v && v->type == Int)
            return static_cast<double>(v->int_val);
        return def;
    }

    bool
    get_bool(const std::string& key, bool def = false) const
    {
        auto* v = get(key);
        return (v && v->type == Bool) ? v->bool_val : def;
    }

    // Serialize to JSON string.
    std::string
    to_json() const
    {
        std::ostringstream ss;
        write_json(ss);
        return ss.str();
    }

    void
    write_json(std::ostringstream& ss) const
    {
        switch (type) {
        case Null:
            ss << "null";
            break;
        case Bool:
            ss << (bool_val ? "true" : "false");
            break;
        case Int:
            ss << int_val;
            break;
        case Double:
            ss << double_val;
            break;
        case String: {
            ss << '"';
            for (char c : string_val) {
                if (c == '"')
                    ss << "\\\"";
                else if (c == '\\')
                    ss << "\\\\";
                else if (c == '\n')
                    ss << "\\n";
                else if (c == '\r')
                    ss << "\\r";
                else if (c == '\t')
                    ss << "\\t";
                else
                    ss << c;
            }
            ss << '"';
            break;
        }
        case Array: {
            ss << '[';
            for (size_t i = 0; i < array_val.size(); i++) {
                if (i > 0)
                    ss << ',';
                array_val[i].write_json(ss);
            }
            ss << ']';
            break;
        }
        case Object: {
            ss << '{';
            for (size_t i = 0; i < object_val.size(); i++) {
                if (i > 0)
                    ss << ',';
                ss << '"';
                for (char c : object_val[i].first) {
                    if (c == '"')
                        ss << "\\\"";
                    else if (c == '\\')
                        ss << "\\\\";
                    else
                        ss << c;
                }
                ss << "\":";
                object_val[i].second.write_json(ss);
            }
            ss << '}';
            break;
        }
        }
    }
};

// Minimal JSON parser (handles the subset needed for JSON-RPC).
class JsonParser
{
    const std::string& src;
    size_t pos = 0;

    void
    skip_ws()
    {
        while (pos < src.size() && (src[pos] == ' ' || src[pos] == '\t' || src[pos] == '\r' || src[pos] == '\n'))
            pos++;
    }

    JsonValue
    parse_string()
    {
        pos++; // skip opening "
        std::string result;
        while (pos < src.size() && src[pos] != '"') {
            if (src[pos] == '\\' && pos + 1 < src.size()) {
                pos++;
                switch (src[pos]) {
                case '"':
                    result += '"';
                    break;
                case '\\':
                    result += '\\';
                    break;
                case 'n':
                    result += '\n';
                    break;
                case 'r':
                    result += '\r';
                    break;
                case 't':
                    result += '\t';
                    break;
                case '/':
                    result += '/';
                    break;
                default:
                    result += src[pos];
                    break;
                }
            } else {
                result += src[pos];
            }
            pos++;
        }
        if (pos < src.size())
            pos++; // skip closing "
        return JsonValue(result);
    }

    JsonValue
    parse_number()
    {
        size_t start = pos;
        bool is_float = false;
        if (src[pos] == '-')
            pos++;
        while (pos < src.size() && src[pos] >= '0' && src[pos] <= '9')
            pos++;
        if (pos < src.size() && src[pos] == '.') {
            is_float = true;
            pos++;
        }
        while (pos < src.size() && src[pos] >= '0' && src[pos] <= '9')
            pos++;
        if (pos < src.size() && (src[pos] == 'e' || src[pos] == 'E')) {
            is_float = true;
            pos++;
            if (pos < src.size() && (src[pos] == '+' || src[pos] == '-'))
                pos++;
            while (pos < src.size() && src[pos] >= '0' && src[pos] <= '9')
                pos++;
        }
        std::string num_str = src.substr(start, pos - start);
        if (is_float)
            return JsonValue(std::stod(num_str));
        return JsonValue(static_cast<int64_t>(std::stoll(num_str)));
    }

    JsonValue
    parse_array()
    {
        pos++; // skip [
        JsonValue arr = JsonValue::make_array();
        skip_ws();
        if (pos < src.size() && src[pos] == ']') {
            pos++;
            return arr;
        }
        while (pos < src.size()) {
            arr.push_back(parse_value());
            skip_ws();
            if (pos < src.size() && src[pos] == ',') {
                pos++;
                continue;
            }
            break;
        }
        skip_ws();
        if (pos < src.size() && src[pos] == ']')
            pos++;
        return arr;
    }

    JsonValue
    parse_object()
    {
        pos++; // skip {
        JsonValue obj = JsonValue::make_object();
        skip_ws();
        if (pos < src.size() && src[pos] == '}') {
            pos++;
            return obj;
        }
        while (pos < src.size()) {
            skip_ws();
            if (pos >= src.size() || src[pos] != '"')
                break;
            auto key = parse_string();
            skip_ws();
            if (pos < src.size() && src[pos] == ':')
                pos++;
            skip_ws();
            obj.set(key.string_val, parse_value());
            skip_ws();
            if (pos < src.size() && src[pos] == ',') {
                pos++;
                continue;
            }
            break;
        }
        skip_ws();
        if (pos < src.size() && src[pos] == '}')
            pos++;
        return obj;
    }

  public:
    explicit JsonParser(const std::string& s) : src(s) {}

    JsonValue
    parse_value()
    {
        skip_ws();
        if (pos >= src.size())
            return JsonValue();
        char c = src[pos];
        if (c == '"')
            return parse_string();
        if (c == '{')
            return parse_object();
        if (c == '[')
            return parse_array();
        if (c == 't') {
            pos += 4;
            return JsonValue(true);
        }
        if (c == 'f') {
            pos += 5;
            return JsonValue(false);
        }
        if (c == 'n') {
            pos += 4;
            return JsonValue();
        }
        return parse_number();
    }
};

static JsonValue
json_parse(const std::string& s)
{
    JsonParser parser(s);
    return parser.parse_value();
}

// ============================================================================
// ETL data model
// ============================================================================

// 100-ns units to nanoseconds.
static constexpr uint64_t FILETIME_TO_NS = 100;

struct ProgramInvokeEvent
{
    uint32_t program_id;
    std::string program_name;
    uint64_t correlation_id;
    uint32_t process_id;
    uint32_t thread_id;
    uint64_t start_time; // 100-ns units (from ETW event field)
    uint64_t end_time;   // 100-ns units
    uint64_t duration;   // 100-ns units
    uint32_t cpu_id;
    uint64_t etw_timestamp; // QPC from event header (for ordering)
};

struct MapHelperEvent
{
    uint32_t program_id;
    uint32_t helper_function_id;
    std::string map_name;
    uint64_t correlation_id;
    uint32_t process_id;
    uint32_t thread_id;
    uint64_t start_time; // 100-ns units
    uint64_t end_time;   // 100-ns units
    uint64_t duration;   // 100-ns units
    uint32_t cpu_id;
    uint64_t etw_timestamp;
};

struct ExtInvokeEvent
{
    uint32_t program_id;
    uint32_t hook_type;
    uint32_t process_id;
    uint32_t thread_id;
    uint64_t ext_start_time;
    uint64_t ext_end_time;
    uint64_t ext_duration;
    uint32_t cpu_id;
    uint64_t etw_timestamp;
};

struct PercentileStats
{
    uint64_t count;
    uint64_t avg_ns;
    uint64_t min_ns;
    uint64_t p50_ns;
    uint64_t p90_ns;
    uint64_t p95_ns;
    uint64_t p99_ns;
    uint64_t p999_ns;
    uint64_t max_ns;
};

// Loaded trace data — fully indexed for fast queries.
struct TraceData
{
    std::string file_path;

    // All raw events, in order.
    std::vector<ProgramInvokeEvent> program_events;
    std::vector<MapHelperEvent> helper_events;
    std::vector<ExtInvokeEvent> ext_events;

    // Indexes: program_id -> indices into program_events / helper_events.
    std::unordered_map<uint32_t, std::vector<size_t>> program_event_index;
    std::unordered_map<uint32_t, std::vector<size_t>> helper_event_by_program;

    // program_id -> sorted durations (100-ns units) for percentile computation.
    std::unordered_map<uint32_t, std::vector<uint64_t>> program_sorted_durations;

    // (program_id, helper_id) -> sorted durations.
    std::map<std::pair<uint32_t, uint32_t>, std::vector<uint64_t>> helper_sorted_durations;

    // correlation_id -> indices into helper_events for O(1) correlation lookup.
    std::unordered_map<uint64_t, std::vector<size_t>> helper_event_by_correlation;

    // correlation_id -> index into program_events (for reverse lookup).
    std::unordered_map<uint64_t, size_t> program_event_by_correlation;

    // (program_id, map_name, helper_function_id) -> sorted durations for per-map stats.
    std::map<std::tuple<uint32_t, std::string, uint32_t>, std::vector<uint64_t>> map_sorted_durations;

    // Program names.
    std::unordered_map<uint32_t, std::string> program_names;

    // Trace metadata.
    uint64_t first_timestamp = 0;
    uint64_t last_timestamp = 0;
    uint64_t timer_resolution = 0;
    uint32_t total_events = 0;
};

// Global loaded traces (keyed by file path).
static std::unordered_map<std::string, std::unique_ptr<TraceData>> g_traces;
static std::mutex g_traces_mutex;

// ============================================================================
// ETL parsing (reuses the same TDH approach as latency.cpp)
// ============================================================================

static const GUID EBPF_CORE_PROVIDER_GUID = {
    0x394f321c, 0x5cf4, 0x404c, {0xaa, 0x34, 0x4d, 0xf1, 0x42, 0x8a, 0x7f, 0x9c}};
static const GUID NET_EBPF_EXT_PROVIDER_GUID = {
    0xf2f2ca01, 0xad02, 0x4a07, {0x9e, 0x90, 0x95, 0xa2, 0x33, 0x4f, 0x36, 0x92}};

static uint32_t
tdh_get_uint32(PEVENT_RECORD event, LPCWSTR prop)
{
    PROPERTY_DATA_DESCRIPTOR d = {};
    d.PropertyName = (ULONGLONG)prop;
    d.ArrayIndex = ULONG_MAX;
    uint32_t v = 0;
    TdhGetProperty(event, 0, nullptr, 1, &d, sizeof(v), (PBYTE)&v);
    return v;
}

static uint64_t
tdh_get_uint64(PEVENT_RECORD event, LPCWSTR prop)
{
    PROPERTY_DATA_DESCRIPTOR d = {};
    d.PropertyName = (ULONGLONG)prop;
    d.ArrayIndex = ULONG_MAX;
    uint64_t v = 0;
    TdhGetProperty(event, 0, nullptr, 1, &d, sizeof(v), (PBYTE)&v);
    return v;
}

static std::string
tdh_get_string(PEVENT_RECORD event, LPCWSTR prop)
{
    PROPERTY_DATA_DESCRIPTOR d = {};
    d.PropertyName = (ULONGLONG)prop;
    d.ArrayIndex = ULONG_MAX;
    ULONG sz = 0;
    if (TdhGetPropertySize(event, 0, nullptr, 1, &d, &sz) != ERROR_SUCCESS || sz == 0)
        return "";
    std::string val(sz, '\0');
    if (TdhGetProperty(event, 0, nullptr, 1, &d, sz, (PBYTE)val.data()) != ERROR_SUCCESS)
        return "";
    while (!val.empty() && val.back() == '\0')
        val.pop_back();
    return val;
}

static void WINAPI
etl_callback(PEVENT_RECORD rec)
{
    TraceData* td = (TraceData*)rec->UserContext;

    bool is_core = IsEqualGUID(rec->EventHeader.ProviderId, EBPF_CORE_PROVIDER_GUID);
    bool is_ext = IsEqualGUID(rec->EventHeader.ProviderId, NET_EBPF_EXT_PROVIDER_GUID);
    if (!is_core && !is_ext)
        return;
    if ((rec->EventHeader.EventDescriptor.Keyword & 0x800) == 0)
        return;

    // Get event name.
    DWORD buf_sz = 0;
    if (TdhGetEventInformation(rec, 0, nullptr, nullptr, &buf_sz) != ERROR_INSUFFICIENT_BUFFER)
        return;
    std::vector<BYTE> buf(buf_sz);
    auto* info = (TRACE_EVENT_INFO*)buf.data();
    if (TdhGetEventInformation(rec, 0, nullptr, info, &buf_sz) != ERROR_SUCCESS)
        return;
    LPCWSTR name = (info->EventNameOffset != 0) ? (LPCWSTR)(buf.data() + info->EventNameOffset) : L"";

    uint64_t ts = rec->EventHeader.TimeStamp.QuadPart;
    if (td->first_timestamp == 0 || ts < td->first_timestamp)
        td->first_timestamp = ts;
    if (ts > td->last_timestamp)
        td->last_timestamp = ts;

    if (is_core && wcscmp(name, L"EbpfProgramLatency") == 0) {
        ProgramInvokeEvent ev;
        ev.program_id = tdh_get_uint32(rec, L"ProgramId");
        ev.program_name = tdh_get_string(rec, L"ProgramName");
        ev.correlation_id = tdh_get_uint64(rec, L"CorrelationId");
        ev.process_id = tdh_get_uint32(rec, L"ProcessId");
        ev.thread_id = tdh_get_uint32(rec, L"ThreadId");
        ev.start_time = tdh_get_uint64(rec, L"StartTime");
        ev.end_time = tdh_get_uint64(rec, L"EndTime");
        ev.duration = tdh_get_uint64(rec, L"Duration");
        ev.cpu_id = tdh_get_uint32(rec, L"CpuId");
        ev.etw_timestamp = ts;

        if (!ev.program_name.empty() && td->program_names.find(ev.program_id) == td->program_names.end()) {
            td->program_names[ev.program_id] = ev.program_name;
        }

        td->program_events.push_back(std::move(ev));
        td->total_events++;
    } else if (is_core && wcscmp(name, L"EbpfMapHelperLatency") == 0) {
        MapHelperEvent ev;
        ev.program_id = tdh_get_uint32(rec, L"ProgramId");
        ev.helper_function_id = tdh_get_uint32(rec, L"HelperFunctionId");
        ev.map_name = tdh_get_string(rec, L"MapName");
        ev.correlation_id = tdh_get_uint64(rec, L"CorrelationId");
        ev.process_id = tdh_get_uint32(rec, L"ProcessId");
        ev.thread_id = tdh_get_uint32(rec, L"ThreadId");
        ev.start_time = tdh_get_uint64(rec, L"StartTime");
        ev.end_time = tdh_get_uint64(rec, L"EndTime");
        ev.duration = tdh_get_uint64(rec, L"Duration");
        ev.cpu_id = tdh_get_uint32(rec, L"CpuId");
        ev.etw_timestamp = ts;

        td->helper_events.push_back(std::move(ev));
        td->total_events++;
    } else if (is_ext && wcscmp(name, L"NetEbpfExtInvokeLatency") == 0) {
        ExtInvokeEvent ev;
        ev.program_id = tdh_get_uint32(rec, L"ProgramId");
        ev.hook_type = tdh_get_uint32(rec, L"HookType");
        ev.process_id = tdh_get_uint32(rec, L"ProcessId");
        ev.thread_id = tdh_get_uint32(rec, L"ThreadId");
        ev.ext_start_time = tdh_get_uint64(rec, L"ExtStartTime");
        ev.ext_end_time = tdh_get_uint64(rec, L"ExtEndTime");
        ev.ext_duration = tdh_get_uint64(rec, L"ExtDuration");
        ev.cpu_id = tdh_get_uint32(rec, L"CpuId");
        ev.etw_timestamp = ts;

        td->ext_events.push_back(std::move(ev));
        td->total_events++;
    }
}

// Build indexes after all events have been loaded.
static void
build_indexes(TraceData& td)
{
    // Program event index.
    for (size_t i = 0; i < td.program_events.size(); i++) {
        auto& ev = td.program_events[i];
        td.program_event_index[ev.program_id].push_back(i);
        td.program_sorted_durations[ev.program_id].push_back(ev.duration);
    }

    // Sort duration vectors for percentile computation.
    for (auto& [pid, durations] : td.program_sorted_durations) {
        std::sort(durations.begin(), durations.end());
    }

    // Program event correlation index.
    for (size_t i = 0; i < td.program_events.size(); i++) {
        auto& ev = td.program_events[i];
        if (ev.correlation_id != 0) {
            td.program_event_by_correlation[ev.correlation_id] = i;
        }
    }

    // Helper event index.
    for (size_t i = 0; i < td.helper_events.size(); i++) {
        auto& ev = td.helper_events[i];
        td.helper_event_by_program[ev.program_id].push_back(i);
        td.helper_sorted_durations[{ev.program_id, ev.helper_function_id}].push_back(ev.duration);
        if (ev.correlation_id != 0) {
            td.helper_event_by_correlation[ev.correlation_id].push_back(i);
        }
        td.map_sorted_durations[{ev.program_id, ev.map_name, ev.helper_function_id}].push_back(ev.duration);
    }

    for (auto& [key, durations] : td.helper_sorted_durations) {
        std::sort(durations.begin(), durations.end());
    }

    for (auto& [key, durations] : td.map_sorted_durations) {
        std::sort(durations.begin(), durations.end());
    }
}

static std::string
load_etl_file(const std::string& file_path)
{
    auto td = std::make_unique<TraceData>();
    td->file_path = file_path;

    // Convert to wide string.
    int wsz = MultiByteToWideChar(CP_UTF8, 0, file_path.c_str(), -1, nullptr, 0);
    std::wstring wpath(wsz, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, file_path.c_str(), -1, wpath.data(), wsz);

    EVENT_TRACE_LOGFILEW logfile = {};
    logfile.LogFileName = wpath.data();
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = etl_callback;
    logfile.Context = td.get();

    TRACEHANDLE handle = OpenTraceW(&logfile);
    if (handle == INVALID_PROCESSTRACE_HANDLE) {
        return "Failed to open ETL file: " + file_path;
    }

    td->timer_resolution = logfile.LogfileHeader.PerfFreq.QuadPart;

    DWORD status = ProcessTrace(&handle, 1, nullptr, nullptr);
    CloseTrace(handle);

    if (status != ERROR_SUCCESS && status != ERROR_CANCELLED) {
        return "Failed to process ETL file, error=" + std::to_string(status);
    }

    build_indexes(*td);

    std::lock_guard<std::mutex> lock(g_traces_mutex);
    g_traces[file_path] = std::move(td);
    return "";
}

// ============================================================================
// Statistics helpers
// ============================================================================

static const char*
helper_function_name(uint32_t id)
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

static PercentileStats
compute_stats(const std::vector<uint64_t>& sorted_durations)
{
    PercentileStats s = {};
    size_t n = sorted_durations.size();
    if (n == 0)
        return s;

    s.count = n;
    uint64_t sum = 0;
    for (auto d : sorted_durations)
        sum += d;
    s.avg_ns = (sum / n) * FILETIME_TO_NS;
    s.min_ns = sorted_durations[0] * FILETIME_TO_NS;
    s.p50_ns = sorted_durations[n * 50 / 100] * FILETIME_TO_NS;
    s.p90_ns = sorted_durations[n * 90 / 100] * FILETIME_TO_NS;
    s.p95_ns = sorted_durations[n * 95 / 100] * FILETIME_TO_NS;
    s.p99_ns = sorted_durations[n * 99 / 100] * FILETIME_TO_NS;
    s.p999_ns = sorted_durations[std::min(n - 1, (size_t)(n * 999 / 1000))] * FILETIME_TO_NS;
    s.max_ns = sorted_durations[n - 1] * FILETIME_TO_NS;
    return s;
}

static JsonValue
stats_to_json(const PercentileStats& s)
{
    auto obj = JsonValue::make_object();
    obj.set("count", JsonValue(s.count));
    obj.set("avg_ns", JsonValue(s.avg_ns));
    obj.set("min_ns", JsonValue(s.min_ns));
    obj.set("p50_ns", JsonValue(s.p50_ns));
    obj.set("p90_ns", JsonValue(s.p90_ns));
    obj.set("p95_ns", JsonValue(s.p95_ns));
    obj.set("p99_ns", JsonValue(s.p99_ns));
    obj.set("p999_ns", JsonValue(s.p999_ns));
    obj.set("max_ns", JsonValue(s.max_ns));
    return obj;
}

static JsonValue
program_event_to_json(const ProgramInvokeEvent& ev)
{
    auto obj = JsonValue::make_object();
    obj.set("program_id", JsonValue(ev.program_id));
    obj.set("program_name", JsonValue(ev.program_name));
    obj.set("correlation_id", JsonValue(ev.correlation_id));
    obj.set("process_id", JsonValue(ev.process_id));
    obj.set("thread_id", JsonValue(ev.thread_id));
    obj.set("start_time", JsonValue(ev.start_time));
    obj.set("end_time", JsonValue(ev.end_time));
    obj.set("duration_100ns", JsonValue(ev.duration));
    obj.set("duration_ns", JsonValue(ev.duration * FILETIME_TO_NS));
    obj.set("cpu_id", JsonValue(ev.cpu_id));
    return obj;
}

static JsonValue
helper_event_to_json(const MapHelperEvent& ev)
{
    auto obj = JsonValue::make_object();
    obj.set("program_id", JsonValue(ev.program_id));
    obj.set("helper_function_id", JsonValue(ev.helper_function_id));
    const char* hname = helper_function_name(ev.helper_function_id);
    obj.set("helper_name", JsonValue(hname ? hname : ("helper_" + std::to_string(ev.helper_function_id)).c_str()));
    obj.set("map_name", JsonValue(ev.map_name));
    obj.set("correlation_id", JsonValue(ev.correlation_id));
    obj.set("process_id", JsonValue(ev.process_id));
    obj.set("thread_id", JsonValue(ev.thread_id));
    obj.set("start_time", JsonValue(ev.start_time));
    obj.set("end_time", JsonValue(ev.end_time));
    obj.set("duration_100ns", JsonValue(ev.duration));
    obj.set("duration_ns", JsonValue(ev.duration * FILETIME_TO_NS));
    obj.set("cpu_id", JsonValue(ev.cpu_id));
    return obj;
}

// ============================================================================
// Tool: get TraceData* or return error
// ============================================================================

static TraceData*
get_trace(const std::string& path, std::string& error)
{
    std::lock_guard<std::mutex> lock(g_traces_mutex);
    auto it = g_traces.find(path);
    if (it == g_traces.end()) {
        error = "No trace loaded for path: " + path + ". Call load_etl first.";
        return nullptr;
    }
    return it->second.get();
}

// ============================================================================
// MCP Tool Implementations
// ============================================================================

// Tool: load_etl
// Params: { "file_path": "<path to .etl file>" }
static JsonValue
tool_load_etl(const JsonValue& params)
{
    std::string path = params.get_string("file_path");
    if (path.empty()) {
        auto err = JsonValue::make_object();
        err.set("error", JsonValue("file_path parameter is required"));
        return err;
    }

    std::string error = load_etl_file(path);
    if (!error.empty()) {
        auto err = JsonValue::make_object();
        err.set("error", JsonValue(error));
        return err;
    }

    std::lock_guard<std::mutex> lock(g_traces_mutex);
    auto& td = g_traces[path];

    auto result = JsonValue::make_object();
    result.set("status", JsonValue("loaded"));
    result.set("file_path", JsonValue(path));
    result.set("total_events", JsonValue(td->total_events));
    result.set("program_invoke_events", JsonValue(static_cast<uint64_t>(td->program_events.size())));
    result.set("map_helper_events", JsonValue(static_cast<uint64_t>(td->helper_events.size())));
    result.set("ext_invoke_events", JsonValue(static_cast<uint64_t>(td->ext_events.size())));
    result.set("unique_programs", JsonValue(static_cast<uint64_t>(td->program_event_index.size())));

    double duration_sec = 0.0;
    if (td->timer_resolution > 0 && td->last_timestamp > td->first_timestamp) {
        duration_sec =
            static_cast<double>(td->last_timestamp - td->first_timestamp) / static_cast<double>(td->timer_resolution);
    }
    result.set("trace_duration_seconds", JsonValue(duration_sec));

    return result;
}

// Tool: unload
// Params: { "file_path": "<path>" }
static JsonValue
tool_unload(const JsonValue& params)
{
    std::string path = params.get_string("file_path");
    std::lock_guard<std::mutex> lock(g_traces_mutex);
    auto it = g_traces.find(path);
    if (it == g_traces.end()) {
        auto err = JsonValue::make_object();
        err.set("error", JsonValue("No trace loaded for: " + path));
        return err;
    }
    g_traces.erase(it);
    auto result = JsonValue::make_object();
    result.set("status", JsonValue("unloaded"));
    result.set("file_path", JsonValue(path));
    return result;
}

// Tool: list_programs
// Params: { "file_path": "<path>" }
static JsonValue
tool_list_programs(const JsonValue& params)
{
    std::string error;
    auto* td = get_trace(params.get_string("file_path"), error);
    if (!td) {
        auto err = JsonValue::make_object();
        err.set("error", JsonValue(error));
        return err;
    }

    auto programs = JsonValue::make_array();
    for (auto& [pid, indices] : td->program_event_index) {
        auto prog = JsonValue::make_object();
        prog.set("program_id", JsonValue(pid));
        auto name_it = td->program_names.find(pid);
        prog.set("program_name", JsonValue(name_it != td->program_names.end() ? name_it->second : ""));
        prog.set("invocation_count", JsonValue(static_cast<uint64_t>(indices.size())));

        // Count helper events for this program.
        auto helper_it = td->helper_event_by_program.find(pid);
        uint64_t helper_count = helper_it != td->helper_event_by_program.end() ? helper_it->second.size() : 0;
        prog.set("helper_event_count", JsonValue(helper_count));

        programs.push_back(prog);
    }

    auto result = JsonValue::make_object();
    result.set("programs", programs);
    return result;
}

// Tool: get_summary
// Params: { "file_path": "<path>" }
// Returns the same info as netsh show latencytrace (table mode).
static JsonValue
tool_get_summary(const JsonValue& params)
{
    std::string error;
    auto* td = get_trace(params.get_string("file_path"), error);
    if (!td) {
        auto err = JsonValue::make_object();
        err.set("error", JsonValue(error));
        return err;
    }

    auto result = JsonValue::make_object();

    // Trace metadata.
    double duration_sec = 0.0;
    if (td->timer_resolution > 0 && td->last_timestamp > td->first_timestamp) {
        duration_sec =
            static_cast<double>(td->last_timestamp - td->first_timestamp) / static_cast<double>(td->timer_resolution);
    }
    result.set("trace_duration_seconds", JsonValue(duration_sec));
    result.set("total_events", JsonValue(td->total_events));

    // Program invocation summary.
    auto prog_summary = JsonValue::make_array();
    for (auto& [pid, sorted_durs] : td->program_sorted_durations) {
        auto entry = JsonValue::make_object();
        entry.set("program_id", JsonValue(pid));
        auto name_it = td->program_names.find(pid);
        entry.set("program_name", JsonValue(name_it != td->program_names.end() ? name_it->second : ""));
        entry.set("statistics", stats_to_json(compute_stats(sorted_durs)));
        prog_summary.push_back(entry);
    }
    result.set("program_invocation_summary", prog_summary);

    // Map helper summary (grouped by program_id, then by helper_id).
    auto helper_summary = JsonValue::make_array();
    // Group by program_id.
    std::map<uint32_t, std::vector<std::pair<uint32_t, const std::vector<uint64_t>*>>> by_prog;
    for (auto& [key, durs] : td->helper_sorted_durations) {
        by_prog[key.first].push_back({key.second, &durs});
    }
    for (auto& [pid, helpers] : by_prog) {
        auto prog_entry = JsonValue::make_object();
        prog_entry.set("program_id", JsonValue(pid));
        auto name_it = td->program_names.find(pid);
        prog_entry.set("program_name", JsonValue(name_it != td->program_names.end() ? name_it->second : ""));

        auto helper_arr = JsonValue::make_array();
        for (auto& [hid, durs_ptr] : helpers) {
            auto h_entry = JsonValue::make_object();
            h_entry.set("helper_function_id", JsonValue(hid));
            const char* hname = helper_function_name(hid);
            h_entry.set("helper_name", JsonValue(hname ? hname : ("helper_" + std::to_string(hid)).c_str()));
            h_entry.set("statistics", stats_to_json(compute_stats(*durs_ptr)));
            helper_arr.push_back(h_entry);
        }
        prog_entry.set("helpers", helper_arr);
        helper_summary.push_back(prog_entry);
    }
    result.set("map_helper_summary", helper_summary);

    return result;
}

// Tool: get_program_summary
// Params: { "file_path": "<path>", "program_id": <id> (0 or omitted = all programs) }
// Returns detailed stats for a single program (or all programs) including all percentiles.
static JsonValue
tool_get_program_summary(const JsonValue& params)
{
    std::string error;
    auto* td = get_trace(params.get_string("file_path"), error);
    if (!td) {
        auto err = JsonValue::make_object();
        err.set("error", JsonValue(error));
        return err;
    }

    auto* pid_param = params.get("program_id");
    bool all_programs = (pid_param == nullptr || (pid_param->type == JsonValue::Int && pid_param->int_val == 0));

    if (all_programs) {
        // Return summary for all programs in a single response.
        auto programs = JsonValue::make_array();
        for (auto& [pid, sorted_durs] : td->program_sorted_durations) {
            auto prog = JsonValue::make_object();
            prog.set("program_id", JsonValue(pid));
            auto name_it = td->program_names.find(pid);
            prog.set("program_name", JsonValue(name_it != td->program_names.end() ? name_it->second : ""));
            prog.set("statistics", stats_to_json(compute_stats(sorted_durs)));

            auto helpers = JsonValue::make_array();
            for (auto& [key, durs] : td->helper_sorted_durations) {
                if (key.first == pid) {
                    auto h = JsonValue::make_object();
                    h.set("helper_function_id", JsonValue(key.second));
                    const char* hname = helper_function_name(key.second);
                    h.set("helper_name", JsonValue(hname ? hname : ("helper_" + std::to_string(key.second)).c_str()));
                    h.set("statistics", stats_to_json(compute_stats(durs)));
                    helpers.push_back(h);
                }
            }
            prog.set("helpers", helpers);
            programs.push_back(prog);
        }

        auto result = JsonValue::make_object();
        result.set("programs", programs);
        return result;
    }

    uint32_t pid = static_cast<uint32_t>(params.get_int("program_id"));
    auto dur_it = td->program_sorted_durations.find(pid);
    if (dur_it == td->program_sorted_durations.end()) {
        auto err = JsonValue::make_object();
        err.set("error", JsonValue("No events found for program_id=" + std::to_string(pid)));
        return err;
    }

    auto result = JsonValue::make_object();
    result.set("program_id", JsonValue(pid));
    auto name_it = td->program_names.find(pid);
    result.set("program_name", JsonValue(name_it != td->program_names.end() ? name_it->second : ""));
    result.set("statistics", stats_to_json(compute_stats(dur_it->second)));

    // Also provide helper summary for this program.
    auto helpers = JsonValue::make_array();
    for (auto& [key, durs] : td->helper_sorted_durations) {
        if (key.first == pid) {
            auto h = JsonValue::make_object();
            h.set("helper_function_id", JsonValue(key.second));
            const char* hname = helper_function_name(key.second);
            h.set("helper_name", JsonValue(hname ? hname : ("helper_" + std::to_string(key.second)).c_str()));
            h.set("statistics", stats_to_json(compute_stats(durs)));
            helpers.push_back(h);
        }
    }
    result.set("helpers", helpers);

    return result;
}

// Tool: get_helper_summary
// Params: { "file_path": "<path>", "program_id": <id>, "helper_function_id": <id> (optional) }
static JsonValue
tool_get_helper_summary(const JsonValue& params)
{
    std::string error;
    auto* td = get_trace(params.get_string("file_path"), error);
    if (!td) {
        auto err = JsonValue::make_object();
        err.set("error", JsonValue(error));
        return err;
    }

    uint32_t pid = static_cast<uint32_t>(params.get_int("program_id"));
    auto* hid_param = params.get("helper_function_id");
    bool filter_hid = (hid_param != nullptr && hid_param->type == JsonValue::Int);
    uint32_t target_hid = filter_hid ? static_cast<uint32_t>(hid_param->int_val) : 0;

    auto helpers = JsonValue::make_array();
    for (auto& [key, durs] : td->helper_sorted_durations) {
        if (key.first != pid)
            continue;
        if (filter_hid && key.second != target_hid)
            continue;

        auto h = JsonValue::make_object();
        h.set("helper_function_id", JsonValue(key.second));
        const char* hname = helper_function_name(key.second);
        h.set("helper_name", JsonValue(hname ? hname : ("helper_" + std::to_string(key.second)).c_str()));
        h.set("statistics", stats_to_json(compute_stats(durs)));
        helpers.push_back(h);
    }

    auto result = JsonValue::make_object();
    result.set("program_id", JsonValue(pid));
    result.set("helpers", helpers);
    return result;
}

// Tool: get_percentile_instance
// Params: { "file_path": "<path>", "program_id": <id>, "percentile": <float 0-100>,
//           "include_helpers": <bool> (optional, default false) }
// Finds the specific program invocation event at the given percentile of duration.
// If include_helpers is true, also returns correlated map helpers and timeline analysis.
static JsonValue
tool_get_percentile_instance(const JsonValue& params)
{
    std::string error;
    auto* td = get_trace(params.get_string("file_path"), error);
    if (!td) {
        auto err = JsonValue::make_object();
        err.set("error", JsonValue(error));
        return err;
    }

    uint32_t pid = static_cast<uint32_t>(params.get_int("program_id"));
    double percentile = params.get_double("percentile", 99.0);
    bool include_helpers = params.get_bool("include_helpers", false);

    auto idx_it = td->program_event_index.find(pid);
    if (idx_it == td->program_event_index.end()) {
        auto err = JsonValue::make_object();
        err.set("error", JsonValue("No events for program_id=" + std::to_string(pid)));
        return err;
    }

    // Sort indices by duration to find the percentile instance.
    std::vector<size_t> sorted_indices = idx_it->second;
    std::sort(sorted_indices.begin(), sorted_indices.end(), [&](size_t a, size_t b) {
        return td->program_events[a].duration < td->program_events[b].duration;
    });

    size_t n = sorted_indices.size();
    size_t target_idx = static_cast<size_t>(std::floor(percentile / 100.0 * n));
    if (target_idx >= n)
        target_idx = n - 1;

    size_t event_idx = sorted_indices[target_idx];
    auto& ev = td->program_events[event_idx];

    auto result = JsonValue::make_object();
    result.set("program_id", JsonValue(pid));
    result.set("percentile", JsonValue(percentile));
    result.set("event_index", JsonValue(static_cast<uint64_t>(event_idx)));
    result.set("rank", JsonValue(static_cast<uint64_t>(target_idx + 1)));
    result.set("total_events", JsonValue(static_cast<uint64_t>(n)));
    result.set("event", program_event_to_json(ev));

    if (include_helpers) {
        // Get correlated helpers via correlation_id (fast) or time window (fallback).
        auto helpers = JsonValue::make_array();
        uint64_t total_helper_duration = 0;

        if (ev.correlation_id != 0) {
            auto it = td->helper_event_by_correlation.find(ev.correlation_id);
            if (it != td->helper_event_by_correlation.end()) {
                for (size_t idx : it->second) {
                    auto& hev = td->helper_events[idx];
                    if (hev.program_id == pid) {
                        helpers.push_back(helper_event_to_json(hev));
                        total_helper_duration += hev.duration;
                    }
                }
            }
        } else {
            auto helper_idx_it = td->helper_event_by_program.find(pid);
            if (helper_idx_it != td->helper_event_by_program.end()) {
                for (size_t idx : helper_idx_it->second) {
                    auto& hev = td->helper_events[idx];
                    if (hev.start_time >= ev.start_time && hev.end_time <= ev.end_time) {
                        helpers.push_back(helper_event_to_json(hev));
                        total_helper_duration += hev.duration;
                    }
                }
            }
        }

        result.set("total_helper_duration_ns", JsonValue(total_helper_duration * FILETIME_TO_NS));
        result.set("helper_count", JsonValue(static_cast<uint64_t>(helpers.array_val.size())));
        result.set("correlated_helpers", helpers);

        // Build gap analysis (timeline).
        uint64_t prog_duration_ns = ev.duration * FILETIME_TO_NS;
        uint64_t helper_total_ns = total_helper_duration * FILETIME_TO_NS;
        uint64_t gap_total_ns = prog_duration_ns - helper_total_ns;
        uint64_t largest_gap_ns = 0;
        int largest_gap_position = -1;

        // Sort helpers by start_time and compute gaps.
        struct HelperTiming
        {
            uint64_t start_time;
            uint64_t end_time;
            size_t index;
        };
        std::vector<HelperTiming> timings;
        if (ev.correlation_id != 0) {
            auto it = td->helper_event_by_correlation.find(ev.correlation_id);
            if (it != td->helper_event_by_correlation.end()) {
                for (size_t idx : it->second) {
                    auto& hev = td->helper_events[idx];
                    if (hev.program_id == pid) {
                        timings.push_back({hev.start_time, hev.end_time, timings.size()});
                    }
                }
            }
        } else {
            auto helper_idx_it = td->helper_event_by_program.find(pid);
            if (helper_idx_it != td->helper_event_by_program.end()) {
                for (size_t idx : helper_idx_it->second) {
                    auto& hev = td->helper_events[idx];
                    if (hev.start_time >= ev.start_time && hev.end_time <= ev.end_time) {
                        timings.push_back({hev.start_time, hev.end_time, timings.size()});
                    }
                }
            }
        }

        std::sort(timings.begin(), timings.end(), [](const HelperTiming& a, const HelperTiming& b) {
            return a.start_time < b.start_time;
        });

        auto gaps = JsonValue::make_array();
        uint64_t prev_end = ev.start_time;
        for (size_t i = 0; i < timings.size(); i++) {
            uint64_t gap = (timings[i].start_time > prev_end) ? (timings[i].start_time - prev_end) * FILETIME_TO_NS : 0;
            if (gap > 0) {
                auto g = JsonValue::make_object();
                g.set("before_helper_index", JsonValue(static_cast<uint64_t>(i)));
                g.set("gap_ns", JsonValue(gap));
                gaps.push_back(g);
            }
            if (gap > largest_gap_ns) {
                largest_gap_ns = gap;
                largest_gap_position = static_cast<int>(i);
            }
            prev_end = timings[i].end_time;
        }
        // Gap after last helper to program end.
        uint64_t trailing_gap = (ev.end_time > prev_end) ? (ev.end_time - prev_end) * FILETIME_TO_NS : 0;
        if (trailing_gap > 0) {
            auto g = JsonValue::make_object();
            g.set("before_helper_index", JsonValue("end"));
            g.set("gap_ns", JsonValue(trailing_gap));
            gaps.push_back(g);
            if (trailing_gap > largest_gap_ns) {
                largest_gap_ns = trailing_gap;
                largest_gap_position = static_cast<int>(timings.size());
            }
        }

        auto timeline = JsonValue::make_object();
        timeline.set("program_duration_ns", JsonValue(prog_duration_ns));
        timeline.set("total_helper_ns", JsonValue(helper_total_ns));
        timeline.set("total_gap_ns", JsonValue(gap_total_ns));
        timeline.set("largest_gap_ns", JsonValue(largest_gap_ns));
        timeline.set("largest_gap_position", JsonValue(largest_gap_position));
        timeline.set("gaps", gaps);
        result.set("timeline", timeline);
    }

    return result;
}

// Tool: get_program_events
// Params: { "file_path": "<path>", "program_id": <id>,
//           "sort_by": "duration"|"time" (default "time"),
//           "order": "asc"|"desc" (default "asc"),
//           "offset": <int> (default 0), "limit": <int> (default 100) }
static JsonValue
tool_get_program_events(const JsonValue& params)
{
    std::string error;
    auto* td = get_trace(params.get_string("file_path"), error);
    if (!td) {
        auto err = JsonValue::make_object();
        err.set("error", JsonValue(error));
        return err;
    }

    uint32_t pid = static_cast<uint32_t>(params.get_int("program_id"));
    std::string sort_by = params.get_string("sort_by", "time");
    std::string order = params.get_string("order", "asc");
    int64_t offset = params.get_int("offset", 0);
    int64_t limit = params.get_int("limit", 100);
    if (limit > 1000)
        limit = 1000;

    auto idx_it = td->program_event_index.find(pid);
    if (idx_it == td->program_event_index.end()) {
        auto err = JsonValue::make_object();
        err.set("error", JsonValue("No events for program_id=" + std::to_string(pid)));
        return err;
    }

    std::vector<size_t> indices = idx_it->second;
    if (sort_by == "duration") {
        std::sort(indices.begin(), indices.end(), [&](size_t a, size_t b) {
            return td->program_events[a].duration < td->program_events[b].duration;
        });
    }
    // Default is by time (already in chronological order from ingestion).

    if (order == "desc") {
        std::reverse(indices.begin(), indices.end());
    }

    size_t total = indices.size();
    size_t start = static_cast<size_t>(std::max(offset, (int64_t)0));
    size_t end = std::min(start + static_cast<size_t>(limit), total);

    auto events = JsonValue::make_array();
    for (size_t i = start; i < end; i++) {
        events.push_back(program_event_to_json(td->program_events[indices[i]]));
    }

    auto result = JsonValue::make_object();
    result.set("program_id", JsonValue(pid));
    result.set("total_events", JsonValue(static_cast<uint64_t>(total)));
    result.set("offset", JsonValue(static_cast<uint64_t>(start)));
    result.set("limit", JsonValue(limit));
    result.set("returned", JsonValue(static_cast<uint64_t>(events.array_val.size())));
    result.set("events", events);
    return result;
}

// Tool: get_invocation_timeline
// Params: { "file_path": "<path>", "program_id": <id>,
//           "correlation_id": <uint64> (preferred),
//           "start_time": <uint64>, "end_time": <uint64> (fallback) }
//
// Returns a timeline of a single program invocation showing each map helper event,
// gaps between events (eBPF instruction execution time), and highlights the largest gap.
static JsonValue
tool_get_invocation_timeline(const JsonValue& params)
{
    std::string error;
    auto* td = get_trace(params.get_string("file_path"), error);
    if (!td) {
        auto err = JsonValue::make_object();
        err.set("error", JsonValue(error));
        return err;
    }

    uint32_t pid = static_cast<uint32_t>(params.get_int("program_id"));
    auto* corr_param = params.get("correlation_id");
    bool use_correlation = (corr_param != nullptr && corr_param->type == JsonValue::Int && corr_param->int_val != 0);

    uint64_t prog_start = 0;
    uint64_t prog_end = 0;
    uint64_t prog_duration = 0;
    uint64_t correlation_id = 0;

    // Collect helper events.
    struct HelperInfo
    {
        size_t event_index;
        uint64_t start_time;
        uint64_t end_time;
        uint64_t duration;
    };
    std::vector<HelperInfo> helper_infos;

    if (use_correlation) {
        correlation_id = static_cast<uint64_t>(corr_param->int_val);

        auto prog_it = td->program_event_by_correlation.find(correlation_id);
        if (prog_it == td->program_event_by_correlation.end()) {
            auto err = JsonValue::make_object();
            err.set("error", JsonValue("No program event for correlation_id=" + std::to_string(correlation_id)));
            return err;
        }
        auto& pev = td->program_events[prog_it->second];
        prog_start = pev.start_time;
        prog_end = pev.end_time;
        prog_duration = pev.duration;

        auto it = td->helper_event_by_correlation.find(correlation_id);
        if (it != td->helper_event_by_correlation.end()) {
            for (size_t idx : it->second) {
                auto& hev = td->helper_events[idx];
                if (hev.program_id == pid) {
                    helper_infos.push_back({idx, hev.start_time, hev.end_time, hev.duration});
                }
            }
        }
    } else {
        prog_start = static_cast<uint64_t>(params.get_int("start_time"));
        prog_end = static_cast<uint64_t>(params.get_int("end_time"));
        prog_duration = prog_end - prog_start;

        auto helper_idx_it = td->helper_event_by_program.find(pid);
        if (helper_idx_it != td->helper_event_by_program.end()) {
            for (size_t idx : helper_idx_it->second) {
                auto& hev = td->helper_events[idx];
                if (hev.start_time >= prog_start && hev.end_time <= prog_end) {
                    helper_infos.push_back({idx, hev.start_time, hev.end_time, hev.duration});
                }
            }
        }
    }

    // Sort by start time.
    std::sort(helper_infos.begin(), helper_infos.end(), [](const HelperInfo& a, const HelperInfo& b) {
        return a.start_time < b.start_time;
    });

    // Build timeline entries: alternating gap and helper events.
    auto timeline_entries = JsonValue::make_array();
    uint64_t total_helper_ns = 0;
    uint64_t largest_gap_ns = 0;
    int largest_gap_position = -1;
    uint64_t prev_end = prog_start;

    for (size_t i = 0; i < helper_infos.size(); i++) {
        // Gap before this helper.
        uint64_t gap_100ns = (helper_infos[i].start_time > prev_end) ? (helper_infos[i].start_time - prev_end) : 0;
        uint64_t gap_ns = gap_100ns * FILETIME_TO_NS;
        if (gap_ns > 0) {
            auto gap_entry = JsonValue::make_object();
            gap_entry.set("type", JsonValue("gap"));
            gap_entry.set("duration_ns", JsonValue(gap_ns));
            gap_entry.set("before_helper_index", JsonValue(static_cast<uint64_t>(i)));
            timeline_entries.push_back(gap_entry);
            if (gap_ns > largest_gap_ns) {
                largest_gap_ns = gap_ns;
                largest_gap_position = static_cast<int>(i);
            }
        }

        // Helper event.
        auto& hev = td->helper_events[helper_infos[i].event_index];
        auto helper_entry = JsonValue::make_object();
        helper_entry.set("type", JsonValue("helper"));
        helper_entry.set("index", JsonValue(static_cast<uint64_t>(i)));
        helper_entry.set(
            "helper_name",
            JsonValue(
                helper_function_name(hev.helper_function_id)
                    ? helper_function_name(hev.helper_function_id)
                    : ("helper_" + std::to_string(hev.helper_function_id)).c_str()));
        helper_entry.set("map_name", JsonValue(hev.map_name));
        helper_entry.set("duration_ns", JsonValue(hev.duration * FILETIME_TO_NS));
        helper_entry.set("start_time", JsonValue(hev.start_time));
        helper_entry.set("end_time", JsonValue(hev.end_time));
        timeline_entries.push_back(helper_entry);

        total_helper_ns += hev.duration * FILETIME_TO_NS;
        prev_end = helper_infos[i].end_time;
    }

    // Trailing gap.
    uint64_t trailing_gap_ns = (prog_end > prev_end) ? (prog_end - prev_end) * FILETIME_TO_NS : 0;
    if (trailing_gap_ns > 0) {
        auto gap_entry = JsonValue::make_object();
        gap_entry.set("type", JsonValue("gap"));
        gap_entry.set("duration_ns", JsonValue(trailing_gap_ns));
        gap_entry.set("position", JsonValue("trailing"));
        timeline_entries.push_back(gap_entry);
        if (trailing_gap_ns > largest_gap_ns) {
            largest_gap_ns = trailing_gap_ns;
            largest_gap_position = static_cast<int>(helper_infos.size());
        }
    }

    uint64_t prog_duration_ns = prog_duration * FILETIME_TO_NS;
    uint64_t total_gap_ns = prog_duration_ns - total_helper_ns;

    auto result = JsonValue::make_object();
    result.set("program_id", JsonValue(pid));
    if (use_correlation) {
        result.set("correlation_id", JsonValue(correlation_id));
    }
    result.set("program_start_time", JsonValue(prog_start));
    result.set("program_end_time", JsonValue(prog_end));
    result.set("program_duration_ns", JsonValue(prog_duration_ns));
    result.set("total_helper_ns", JsonValue(total_helper_ns));
    result.set("total_gap_ns", JsonValue(total_gap_ns));
    result.set("helper_count", JsonValue(static_cast<uint64_t>(helper_infos.size())));
    result.set("largest_gap_ns", JsonValue(largest_gap_ns));
    result.set("largest_gap_position", JsonValue(largest_gap_position));
    result.set("helper_pct", JsonValue(prog_duration_ns > 0 ? (100.0 * total_helper_ns / prog_duration_ns) : 0.0));
    result.set("timeline", timeline_entries);
    return result;
}

// Tool: get_map_summary
// Params: { "file_path": "<path>", "program_id": <id>, "map_name": <string> (optional) }
//
// Returns aggregate latency statistics grouped by (map_name, helper_function_id)
// for a given program. If map_name is provided, filters to that specific map.
static JsonValue
tool_get_map_summary(const JsonValue& params)
{
    std::string error;
    auto* td = get_trace(params.get_string("file_path"), error);
    if (!td) {
        auto err = JsonValue::make_object();
        err.set("error", JsonValue(error));
        return err;
    }

    uint32_t pid = static_cast<uint32_t>(params.get_int("program_id"));
    std::string filter_map = params.get_string("map_name", "");

    auto maps = JsonValue::make_array();
    for (auto& [key, durs] : td->map_sorted_durations) {
        auto& [k_pid, k_map, k_hid] = key;
        if (k_pid != pid)
            continue;
        if (!filter_map.empty() && k_map != filter_map)
            continue;

        auto entry = JsonValue::make_object();
        entry.set("map_name", JsonValue(k_map));
        entry.set("helper_function_id", JsonValue(k_hid));
        const char* hname = helper_function_name(k_hid);
        entry.set("helper_name", JsonValue(hname ? hname : ("helper_" + std::to_string(k_hid)).c_str()));
        entry.set("statistics", stats_to_json(compute_stats(durs)));
        maps.push_back(entry);
    }

    auto result = JsonValue::make_object();
    result.set("program_id", JsonValue(pid));
    auto name_it = td->program_names.find(pid);
    result.set("program_name", JsonValue(name_it != td->program_names.end() ? name_it->second : ""));
    if (!filter_map.empty()) {
        result.set("filter_map_name", JsonValue(filter_map));
    }
    result.set("maps", maps);
    return result;
}

// Tool: get_percentile_comparison
// Params: { "file_path": "<path>", "program_id": <id>,
//           "percentiles": [<float>, ...] (e.g. [50, 90, 99]),
//           "include_helpers": <bool> (optional, default false) }
//
// Returns multiple percentile instances in one call for easy comparison.
// Each entry includes the program event and optionally correlated helpers + timeline.
static JsonValue
tool_get_percentile_comparison(const JsonValue& params)
{
    std::string error;
    auto* td = get_trace(params.get_string("file_path"), error);
    if (!td) {
        auto err = JsonValue::make_object();
        err.set("error", JsonValue(error));
        return err;
    }

    uint32_t pid = static_cast<uint32_t>(params.get_int("program_id"));
    bool include_helpers = params.get_bool("include_helpers", false);

    auto* pcts_param = params.get("percentiles");
    std::vector<double> percentiles;
    if (pcts_param && pcts_param->type == JsonValue::Array) {
        for (auto& v : pcts_param->array_val) {
            if (v.type == JsonValue::Double)
                percentiles.push_back(v.double_val);
            else if (v.type == JsonValue::Int)
                percentiles.push_back(static_cast<double>(v.int_val));
        }
    }
    if (percentiles.empty()) {
        percentiles = {50, 90, 99};
    }

    auto idx_it = td->program_event_index.find(pid);
    if (idx_it == td->program_event_index.end()) {
        auto err = JsonValue::make_object();
        err.set("error", JsonValue("No events for program_id=" + std::to_string(pid)));
        return err;
    }

    // Sort indices by duration once for all percentiles.
    std::vector<size_t> sorted_indices = idx_it->second;
    std::sort(sorted_indices.begin(), sorted_indices.end(), [&](size_t a, size_t b) {
        return td->program_events[a].duration < td->program_events[b].duration;
    });
    size_t n = sorted_indices.size();

    auto entries = JsonValue::make_array();
    for (double pct : percentiles) {
        size_t target_idx = static_cast<size_t>(std::floor(pct / 100.0 * n));
        if (target_idx >= n)
            target_idx = n - 1;

        size_t event_idx = sorted_indices[target_idx];
        auto& ev = td->program_events[event_idx];

        auto entry = JsonValue::make_object();
        entry.set("percentile", JsonValue(pct));
        entry.set("rank", JsonValue(static_cast<uint64_t>(target_idx + 1)));
        entry.set("event", program_event_to_json(ev));

        if (include_helpers) {
            auto helpers = JsonValue::make_array();
            uint64_t total_helper_duration = 0;

            struct HelperTiming
            {
                uint64_t start_time;
                uint64_t end_time;
                uint64_t duration;
            };
            std::vector<HelperTiming> timings;

            if (ev.correlation_id != 0) {
                auto it = td->helper_event_by_correlation.find(ev.correlation_id);
                if (it != td->helper_event_by_correlation.end()) {
                    for (size_t idx : it->second) {
                        auto& hev = td->helper_events[idx];
                        if (hev.program_id == pid) {
                            helpers.push_back(helper_event_to_json(hev));
                            total_helper_duration += hev.duration;
                            timings.push_back({hev.start_time, hev.end_time, hev.duration});
                        }
                    }
                }
            } else {
                auto helper_idx_it = td->helper_event_by_program.find(pid);
                if (helper_idx_it != td->helper_event_by_program.end()) {
                    for (size_t idx : helper_idx_it->second) {
                        auto& hev = td->helper_events[idx];
                        if (hev.start_time >= ev.start_time && hev.end_time <= ev.end_time) {
                            helpers.push_back(helper_event_to_json(hev));
                            total_helper_duration += hev.duration;
                            timings.push_back({hev.start_time, hev.end_time, hev.duration});
                        }
                    }
                }
            }

            entry.set("total_helper_duration_ns", JsonValue(total_helper_duration * FILETIME_TO_NS));
            entry.set("helper_count", JsonValue(static_cast<uint64_t>(helpers.array_val.size())));
            entry.set("correlated_helpers", helpers);

            // Gap analysis.
            std::sort(timings.begin(), timings.end(), [](const HelperTiming& a, const HelperTiming& b) {
                return a.start_time < b.start_time;
            });

            uint64_t prog_duration_ns = ev.duration * FILETIME_TO_NS;
            uint64_t helper_total_ns = total_helper_duration * FILETIME_TO_NS;
            uint64_t largest_gap_ns = 0;
            int largest_gap_pos = -1;
            uint64_t prev_end = ev.start_time;
            for (size_t i = 0; i < timings.size(); i++) {
                uint64_t gap =
                    (timings[i].start_time > prev_end) ? (timings[i].start_time - prev_end) * FILETIME_TO_NS : 0;
                if (gap > largest_gap_ns) {
                    largest_gap_ns = gap;
                    largest_gap_pos = static_cast<int>(i);
                }
                prev_end = timings[i].end_time;
            }
            uint64_t trailing = (ev.end_time > prev_end) ? (ev.end_time - prev_end) * FILETIME_TO_NS : 0;
            if (trailing > largest_gap_ns) {
                largest_gap_ns = trailing;
                largest_gap_pos = static_cast<int>(timings.size());
            }

            auto timeline = JsonValue::make_object();
            timeline.set("program_duration_ns", JsonValue(prog_duration_ns));
            timeline.set("total_helper_ns", JsonValue(helper_total_ns));
            timeline.set("total_gap_ns", JsonValue(prog_duration_ns - helper_total_ns));
            timeline.set("largest_gap_ns", JsonValue(largest_gap_ns));
            timeline.set("largest_gap_position", JsonValue(largest_gap_pos));
            timeline.set(
                "helper_pct", JsonValue(prog_duration_ns > 0 ? (100.0 * helper_total_ns / prog_duration_ns) : 0.0));
            entry.set("timeline", timeline);
        }

        entries.push_back(entry);
    }

    auto result = JsonValue::make_object();
    result.set("program_id", JsonValue(pid));
    auto name_it = td->program_names.find(pid);
    result.set("program_name", JsonValue(name_it != td->program_names.end() ? name_it->second : ""));
    result.set("total_events", JsonValue(static_cast<uint64_t>(n)));
    result.set("comparisons", entries);
    return result;
}

// Tool: get_correlated_map_helpers
// Params: { "file_path": "<path>", "program_id": <id>,
//           "correlation_id": <uint64> (preferred, O(1) lookup),
//           "start_time": <uint64>, "end_time": <uint64> (fallback, time-window scan),
//           "thread_id": <uint32> (optional, for stricter matching with time-window mode) }
//
// Finds all map helper events correlated with a program invocation.
// If correlation_id is provided, uses the indexed lookup (fast).
// Otherwise falls back to scanning by time window.
static JsonValue
tool_get_correlated_map_helpers(const JsonValue& params)
{
    std::string error;
    auto* td = get_trace(params.get_string("file_path"), error);
    if (!td) {
        auto err = JsonValue::make_object();
        err.set("error", JsonValue(error));
        return err;
    }

    uint32_t pid = static_cast<uint32_t>(params.get_int("program_id"));
    auto* corr_param = params.get("correlation_id");
    bool use_correlation = (corr_param != nullptr && corr_param->type == JsonValue::Int && corr_param->int_val != 0);

    auto helpers = JsonValue::make_array();
    uint64_t total_helper_duration = 0;
    uint64_t prog_start = 0;
    uint64_t prog_end = 0;

    if (use_correlation) {
        uint64_t corr_id = static_cast<uint64_t>(corr_param->int_val);

        // Look up program event to get start/end times for the response.
        auto prog_it = td->program_event_by_correlation.find(corr_id);
        if (prog_it != td->program_event_by_correlation.end()) {
            auto& pev = td->program_events[prog_it->second];
            prog_start = pev.start_time;
            prog_end = pev.end_time;
        }

        // O(1) lookup of correlated helpers by correlation_id.
        auto it = td->helper_event_by_correlation.find(corr_id);
        if (it != td->helper_event_by_correlation.end()) {
            for (size_t idx : it->second) {
                auto& hev = td->helper_events[idx];
                if (hev.program_id == pid) {
                    helpers.push_back(helper_event_to_json(hev));
                    total_helper_duration += hev.duration;
                }
            }
        }
    } else {
        // Fallback: time-window scan.
        prog_start = static_cast<uint64_t>(params.get_int("start_time"));
        prog_end = static_cast<uint64_t>(params.get_int("end_time"));
        auto* tid_param = params.get("thread_id");
        bool filter_tid = (tid_param != nullptr && tid_param->type == JsonValue::Int);
        uint32_t target_tid = filter_tid ? static_cast<uint32_t>(tid_param->int_val) : 0;

        auto helper_idx_it = td->helper_event_by_program.find(pid);
        if (helper_idx_it != td->helper_event_by_program.end()) {
            for (size_t idx : helper_idx_it->second) {
                auto& hev = td->helper_events[idx];
                if (hev.start_time >= prog_start && hev.end_time <= prog_end) {
                    if (filter_tid && hev.thread_id != target_tid)
                        continue;
                    helpers.push_back(helper_event_to_json(hev));
                    total_helper_duration += hev.duration;
                }
            }
        }
    }

    auto result = JsonValue::make_object();
    result.set("program_id", JsonValue(pid));
    if (use_correlation) {
        result.set("correlation_id", JsonValue(static_cast<uint64_t>(corr_param->int_val)));
    }
    result.set("program_start_time", JsonValue(prog_start));
    result.set("program_end_time", JsonValue(prog_end));
    result.set("program_duration_ns", JsonValue((prog_end - prog_start) * FILETIME_TO_NS));
    result.set("total_helper_duration_ns", JsonValue(total_helper_duration * FILETIME_TO_NS));
    result.set("count", JsonValue(static_cast<uint64_t>(helpers.array_val.size())));
    result.set("correlated_helpers", helpers);
    return result;
}

// ============================================================================
// MCP Protocol Implementation (JSON-RPC 2.0 over stdio)
// ============================================================================

// Build a JSON-RPC 2.0 response.
static std::string
make_response(const JsonValue& id, const JsonValue& result_val)
{
    auto resp = JsonValue::make_object();
    resp.set("jsonrpc", JsonValue("2.0"));
    resp.set("id", id);
    resp.set("result", result_val);
    return resp.to_json();
}

static std::string
make_error_response(const JsonValue& id, int code, const std::string& message)
{
    auto err = JsonValue::make_object();
    err.set("code", JsonValue(code));
    err.set("message", JsonValue(message));

    auto resp = JsonValue::make_object();
    resp.set("jsonrpc", JsonValue("2.0"));
    resp.set("id", id);
    resp.set("error", err);
    return resp.to_json();
}

// Tool descriptor for tools/list.
// params: (name, type, description, required, items_type)
// items_type is optional and only used for array types (e.g. "number" for an array of numbers).
static JsonValue
make_tool_descriptor(
    const std::string& name,
    const std::string& description,
    const std::vector<std::tuple<std::string, std::string, std::string, bool, std::string>>& params)
{
    auto tool = JsonValue::make_object();
    tool.set("name", JsonValue(name));
    tool.set("description", JsonValue(description));

    auto input_schema = JsonValue::make_object();
    input_schema.set("type", JsonValue("object"));

    auto properties = JsonValue::make_object();
    auto required_arr = JsonValue::make_array();

    for (auto& [pname, ptype, pdesc, preq, pitems] : params) {
        auto prop = JsonValue::make_object();
        prop.set("type", JsonValue(ptype));
        prop.set("description", JsonValue(pdesc));
        if (ptype == "array" && !pitems.empty()) {
            auto items = JsonValue::make_object();
            items.set("type", JsonValue(pitems));
            prop.set("items", items);
        }
        properties.set(pname, prop);
        if (preq) {
            required_arr.push_back(JsonValue(pname));
        }
    }

    input_schema.set("properties", properties);
    input_schema.set("required", required_arr);
    tool.set("inputSchema", input_schema);
    return tool;
}

static JsonValue
get_tool_list()
{
    auto tools = JsonValue::make_array();

    tools.push_back(make_tool_descriptor(
        "load_etl",
        "Load and index an eBPF latency ETL trace file. Must be called before querying.",
        {{"file_path", "string", "Absolute path to the .etl file", true, ""}}));

    tools.push_back(make_tool_descriptor(
        "unload",
        "Release a previously loaded ETL trace from memory.",
        {{"file_path", "string", "Path of the previously loaded .etl file", true, ""}}));

    tools.push_back(make_tool_descriptor(
        "list_programs",
        "List all eBPF program IDs and names found in the loaded trace, with event counts.",
        {{"file_path", "string", "Path of the loaded .etl file", true, ""}}));

    tools.push_back(make_tool_descriptor(
        "get_summary",
        "Get an overall latency report for the trace (same as netsh ebpf show latencytrace). "
        "Includes per-program invocation statistics (count, avg, P50, P90, P95, P99, P99.9, max) "
        "and per-helper statistics grouped by program.",
        {{"file_path", "string", "Path of the loaded .etl file", true, ""}}));

    tools.push_back(make_tool_descriptor(
        "get_program_summary",
        "Get detailed latency statistics for a specific eBPF program ID (or all programs if program_id=0), "
        "including all percentiles (P50, P90, P95, P99, P99.9) and associated map helper breakdowns.",
        {{"file_path", "string", "Path of the loaded .etl file", true, ""},
         {"program_id", "integer", "The eBPF program ID to query (0 or omit for all programs)", false, ""}}));

    tools.push_back(make_tool_descriptor(
        "get_helper_summary",
        "Get latency statistics for map helper functions of a specific program. "
        "Optionally filter by helper_function_id.",
        {{"file_path", "string", "Path of the loaded .etl file", true, ""},
         {"program_id", "integer", "The eBPF program ID", true, ""},
         {"helper_function_id", "integer", "Optional: filter to a specific BPF_FUNC_xxx ID", false, ""}}));

    tools.push_back(make_tool_descriptor(
        "get_percentile_instance",
        "Find the specific program invocation event at a given latency percentile (e.g., P99, P99.9). "
        "Returns the full event record including correlation_id, timestamps, thread ID, CPU, and duration. "
        "Set include_helpers=true to also return correlated map helpers and timeline gap analysis "
        "in a single call (no need to call get_correlated_map_helpers separately).",
        {{"file_path", "string", "Path of the loaded .etl file", true, ""},
         {"program_id", "integer", "The eBPF program ID", true, ""},
         {"percentile", "number", "Percentile value (0-100), e.g. 99 for P99, 99.9 for P99.9", true, ""},
         {"include_helpers",
          "boolean",
          "If true, include correlated map helpers and gap analysis (default: false)",
          false,
          ""}}));

    tools.push_back(make_tool_descriptor(
        "get_program_events",
        "List program invocation events for a given program ID, with pagination and sorting. "
        "Useful for browsing raw events or finding outliers.",
        {{"file_path", "string", "Path of the loaded .etl file", true, ""},
         {"program_id", "integer", "The eBPF program ID", true, ""},
         {"sort_by", "string", "Sort by 'duration' or 'time' (default: 'time')", false, ""},
         {"order", "string", "'asc' or 'desc' (default: 'asc')", false, ""},
         {"offset", "integer", "Pagination offset (default: 0)", false, ""},
         {"limit", "integer", "Max events to return, up to 1000 (default: 100)", false, ""}}));

    tools.push_back(make_tool_descriptor(
        "get_correlated_map_helpers",
        "Given a program invocation's correlation_id (preferred, O(1) lookup) or time window "
        "(start_time, end_time) and program_id, find all map helper calls that executed within "
        "that invocation. This enables drill-down from a high-latency program invocation to the "
        "specific map operations that contributed to it.",
        {{"file_path", "string", "Path of the loaded .etl file", true, ""},
         {"program_id", "integer", "The eBPF program ID", true, ""},
         {"correlation_id", "integer", "Correlation ID from program event (preferred, fast O(1) lookup)", false, ""},
         {"start_time", "integer", "Program invocation start_time (fallback if no correlation_id)", false, ""},
         {"end_time", "integer", "Program invocation end_time (fallback if no correlation_id)", false, ""},
         {"thread_id", "integer", "Optional: filter to a specific thread ID (time-window mode only)", false, ""}}));

    tools.push_back(make_tool_descriptor(
        "get_invocation_timeline",
        "Get a detailed timeline of a single program invocation showing each map helper event "
        "interleaved with gaps (eBPF instruction execution time between map calls). "
        "Highlights the largest gap which often explains tail latency spikes. "
        "Accepts correlation_id (preferred) or start_time/end_time.",
        {{"file_path", "string", "Path of the loaded .etl file", true, ""},
         {"program_id", "integer", "The eBPF program ID", true, ""},
         {"correlation_id", "integer", "Correlation ID from program event (preferred)", false, ""},
         {"start_time", "integer", "Program invocation start_time (fallback)", false, ""},
         {"end_time", "integer", "Program invocation end_time (fallback)", false, ""}}));

    tools.push_back(make_tool_descriptor(
        "get_map_summary",
        "Get aggregate latency statistics for map operations broken down by individual map name "
        "and helper function (lookup, update, delete). Shows count, avg, P50, P90, P99, max for "
        "each (map_name, operation) pair. Optionally filter to a specific map.",
        {{"file_path", "string", "Path of the loaded .etl file", true, ""},
         {"program_id", "integer", "The eBPF program ID", true, ""},
         {"map_name", "string", "Optional: filter to a specific map name", false, ""}}));

    tools.push_back(make_tool_descriptor(
        "get_percentile_comparison",
        "Compare multiple percentile instances of a program in a single call. "
        "Returns the program event at each requested percentile with optional "
        "correlated helpers and timeline gap analysis. Ideal for comparing P50 vs P90 vs P99.",
        {{"file_path", "string", "Path of the loaded .etl file", true, ""},
         {"program_id", "integer", "The eBPF program ID", true, ""},
         {"percentiles", "array", "Array of percentile values (default: [50, 90, 99])", false, "number"},
         {"include_helpers",
          "boolean",
          "If true, include correlated helpers and gap analysis for each (default: false)",
          false,
          ""}}));

    return tools;
}

// Route a tools/call request to the appropriate handler.
static JsonValue
dispatch_tool(const std::string& tool_name, const JsonValue& arguments)
{
    if (tool_name == "load_etl")
        return tool_load_etl(arguments);
    if (tool_name == "unload")
        return tool_unload(arguments);
    if (tool_name == "list_programs")
        return tool_list_programs(arguments);
    if (tool_name == "get_summary")
        return tool_get_summary(arguments);
    if (tool_name == "get_program_summary")
        return tool_get_program_summary(arguments);
    if (tool_name == "get_helper_summary")
        return tool_get_helper_summary(arguments);
    if (tool_name == "get_percentile_instance")
        return tool_get_percentile_instance(arguments);
    if (tool_name == "get_program_events")
        return tool_get_program_events(arguments);
    if (tool_name == "get_correlated_map_helpers")
        return tool_get_correlated_map_helpers(arguments);
    if (tool_name == "get_invocation_timeline")
        return tool_get_invocation_timeline(arguments);
    if (tool_name == "get_map_summary")
        return tool_get_map_summary(arguments);
    if (tool_name == "get_percentile_comparison")
        return tool_get_percentile_comparison(arguments);

    auto err = JsonValue::make_object();
    err.set("error", JsonValue("Unknown tool: " + tool_name));
    return err;
}

// Process a single JSON-RPC request and return the response string.
static std::string
process_request(const JsonValue& request)
{
    auto id = request.get("id") ? *request.get("id") : JsonValue();
    std::string method = request.get_string("method");

    // MCP lifecycle methods.
    if (method == "initialize") {
        auto result = JsonValue::make_object();
        result.set("protocolVersion", JsonValue("2024-11-05"));

        auto capabilities = JsonValue::make_object();
        auto tools_cap = JsonValue::make_object();
        tools_cap.set("listChanged", JsonValue(false));
        capabilities.set("tools", tools_cap);
        result.set("capabilities", capabilities);

        auto server_info = JsonValue::make_object();
        server_info.set("name", JsonValue("ebpf-latency-mcp-server"));
        server_info.set("version", JsonValue("1.0.0"));
        result.set("serverInfo", server_info);

        return make_response(id, result);
    }

    if (method == "notifications/initialized") {
        // No response needed for notifications.
        return "";
    }

    if (method == "tools/list") {
        auto result = JsonValue::make_object();
        result.set("tools", get_tool_list());
        return make_response(id, result);
    }

    if (method == "tools/call") {
        auto* params = request.get("params");
        if (!params) {
            return make_error_response(id, -32602, "Missing params");
        }

        std::string tool_name = params->get_string("name");
        auto* arguments = params->get("arguments");
        JsonValue args = arguments ? *arguments : JsonValue::make_object();

        auto tool_result = dispatch_tool(tool_name, args);

        // Wrap in MCP tool result format.
        auto content_item = JsonValue::make_object();
        content_item.set("type", JsonValue("text"));
        content_item.set("text", JsonValue(tool_result.to_json()));

        auto content = JsonValue::make_array();
        content.push_back(content_item);

        auto result = JsonValue::make_object();

        // Check if the tool returned an error.
        auto* err_field = tool_result.get("error");
        result.set("isError", JsonValue(err_field != nullptr));
        result.set("content", content);

        return make_response(id, result);
    }

    if (method == "ping") {
        return make_response(id, JsonValue::make_object());
    }

    return make_error_response(id, -32601, "Method not found: " + method);
}

// ============================================================================
// Main: stdio JSON-RPC message loop
// ============================================================================

int
main()
{
    // Set stdin/stdout to binary mode to avoid CR/LF issues.
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);

    // Log to stderr so it doesn't interfere with the JSON-RPC channel.
    fprintf(stderr, "ebpf-latency-mcp-server started. Waiting for JSON-RPC requests on stdin.\n");

    std::string line;
    while (std::getline(std::cin, line)) {
        // Skip empty lines.
        if (line.empty() || (line.size() == 1 && line[0] == '\r'))
            continue;

        // Trim trailing \r if present.
        if (!line.empty() && line.back() == '\r')
            line.pop_back();

        JsonValue request = json_parse(line);
        std::string response = process_request(request);

        if (!response.empty()) {
            // Write response followed by newline.
            std::cout << response << "\n";
            std::cout.flush();
        }
    }

    fprintf(stderr, "ebpf-latency-mcp-server: stdin closed, exiting.\n");
    return 0;
}
