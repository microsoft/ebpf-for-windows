// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <chrono>
#include <filesystem>
#include <format>
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
        std::cout << std::vformat(fmt, std::make_format_args(args...)) << "\n";
    }
}

#define LOG_ERROR(fmt, ...) _log(log_level::LOG_ERROR, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...) _log(log_level::LOG_WARN, fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...) _log(log_level::LOG_INFO, fmt, ##__VA_ARGS__)
#define LOG_VERBOSE(fmt, ...) _log(log_level::LOG_VERBOSE, fmt, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) _log(log_level::LOG_DEBUG, fmt, ##__VA_ARGS__)

// Test control info.
struct test_control_info
{
    // The number of threads allocated per jit program.
    uint32_t threads_count{0};

    // The run time for each jit program test thread in minutes.
    uint32_t duration_minutes{0};

    // Flag to enable verbose progress output.
    bool verbose_output{false};

    // Flag to enable continous stop-and-restart of the extension.
    bool extension_restart_enabled{false};

    // Delay between extension restarts (in milliseconds).
    uint32_t extension_restart_delay_ms{0};

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
};

using test_thread_function_t = void (*)(const stress_test_thread_context& test_params);
struct test_program_attributes
{
    std::string jit_file_name{};
    std::string native_file_name{};
    std::string extension_name{};
    test_thread_function_t test_thread_function{nullptr};
    bpf_prog_type program_type{BPF_PROG_TYPE_UNSPEC};
    ebpf_execution_type_t execution_type{EBPF_EXECUTION_ANY};
};

inline std::variant<bool, test_program_attributes>
get_jit_program_attributes(const std::string& program_name);

// The query_supported_program_names() call is 'exported' by both the user and kernel mode test suites.
const std::vector<std::string>
query_supported_program_names();

// The test_process_cleanup() call is 'exported' by both the user and kernel mode test suites.
void
test_process_cleanup();
