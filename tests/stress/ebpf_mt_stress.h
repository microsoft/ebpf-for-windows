// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf/bpf.h"
#include "bpf/libbpf.h"

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <format>
#include <functional>
#include <intsafe.h>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <ranges>
#include <semaphore>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <variant>

// Logging support
enum class log_level : uint32_t
{
    LOG_ERROR = 1,
    LOG_WARN,
    LOG_INFO,
    LOG_VERBOSE,
    LOG_DEBUG
};

template <typename... Args>
inline static void
_log(log_level msg_level, const std::string_view& fmt, Args&&... args)
{
    extern log_level cur_log_level;
    if (msg_level <= cur_log_level) {
        std::cerr << std::vformat(fmt, std::make_format_args(args...)) << "\n";
    }
}

#define LOG_ERROR(fmt, ...) _log(log_level::LOG_ERROR, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...) _log(log_level::LOG_WARN, fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...) _log(log_level::LOG_INFO, fmt, ##__VA_ARGS__)
#define LOG_VERBOSE(fmt, ...) _log(log_level::LOG_VERBOSE, fmt, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) _log(log_level::LOG_DEBUG, fmt, ##__VA_ARGS__)

// Default values for test_control_info fields.
constexpr uint32_t DEFAULT_DURATION_MINUTES = 1;
constexpr uint32_t DEFAULT_ATTACH_DETACH_DELAY_MS = 10;
constexpr uint32_t DEFAULT_UM_INVOKE_THREAD_COUNT = 4;
inline uint32_t
default_km_invoke_thread_count()
{
    return static_cast<uint32_t>(std::thread::hardware_concurrency());
}

// Test control info.
struct test_control_info
{
    // The number of invoke worker threads for the race tests.
    uint32_t threads_count{0};

    // The run time for each race test in minutes.
    uint32_t duration_minutes{0};

    // Flag to enable verbose progress output.
    bool verbose_output{false};

    // Flag to enable continous stop-and-restart of the extension.
    bool extension_restart_enabled{false};

    // Delay between extension restarts (in milliseconds).
    uint32_t extension_restart_delay_ms{0};

    // Delay between detach/attach operations in the race thread (in milliseconds).
    uint32_t attach_detach_delay_ms{0};

    // Programs to load.
    std::vector<std::string> programs;

    // Use unique 'native' programs (used internally by specific tests).
    bool use_unique_native_programs{false};
};

test_control_info
get_test_control_info();

// Thread context. One instance per test thread (field usage varies by test).
struct stress_test_thread_context
{
    uint32_t thread_index{0};
    std::string file_name;
    bpf_prog_type program_type;
    ebpf_execution_type_t execution_type;
    uint32_t duration_minutes{0};
    fd_t map_fd;
    ebpf_result_t result;
    std::atomic<size_t>* failure_count;
};

using test_thread_function_t = void (*)(const stress_test_thread_context& test_params);
struct test_program_attributes
{
    std::string jit_file_name{};
    std::string native_file_name{};
    std::string extension_name{};
    test_thread_function_t test_thread_function{nullptr};
    bpf_prog_type program_type{BPF_PROG_TYPE_UNSPEC};
};

inline std::variant<bool, test_program_attributes>
get_jit_program_attributes(const std::string& program_name);

// The test_process_cleanup() call is 'exported' by both the user and kernel mode test suites.
void
test_process_cleanup();

// Common 2-thread race pattern used by UM and KM stress tests.
// Invoke worker thread(s) continuously invoke the program while one thread repeatedly detaches and reattaches it.
bool
run_attach_invoke_detach_race(
    const std::function<void()>& invoke_routine,
    const std::function<void(bool extension_restarting)>& detach_routine,
    const std::function<void(bool extension_restarting)>& attach_routine,
    uint32_t duration_minutes,
    uint32_t invoke_thread_count,
    uint32_t attach_detach_delay_ms,
    bool extension_restart_enabled = false,
    uint32_t extension_restart_delay_ms = 0,
    const std::function<bool()>& extension_restart_routine = {});