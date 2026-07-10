// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "api_internal.h"
#include "bpf/libbpf.h"
#include "catch_wrapper.hpp"
#include "common_tests.h"
#include "ebpf_mt_stress.h"
#include "ebpf_structs.h"
#include "misc_helper.h"
#include "program_helper.h"
#include "sample_ext_helper.h"
#include "sample_ext_test_common.h"
#include "service_helper.h"
#include "socket_helper.h"
#include "socket_tests_common.h"

#include <windows.h>
#include <atomic>
#include <io.h>
#include <vector>

constexpr uint32_t DEFAULT_KM_NATIVE_MT_THREAD_COUNT = 32;
constexpr uint32_t DEFAULT_KM_NATIVE_MT_DURATION_MINUTES = 10;

// Note: The 'program' and 'execution' types are not required for km tests.
static const std::map<std::string, test_program_attributes> _test_program_info = {
    {{"cgroup_sock_addr"},
     {{"cgroup_sock_addr.o"}, {"cgroup_sock_addr.sys"}, {"netebpfext"}, nullptr, BPF_PROG_TYPE_UNSPEC}}};

// Structure to store bpf_object_ptr elements.  A fixed-size table of these entries is shared between the 'creator',
// 'attacher' and the 'destroyer' threads.
struct object_table_entry
{
    std::unique_ptr<std::mutex> lock{nullptr};
    _Guarded_by_(lock) bool available { true };
    _Guarded_by_(lock) bpf_object_ptr object { nullptr };
    _Guarded_by_(lock) bool loaded { false };
    bool attach{false};

    // The following fields are for debugging this test itself.
    uint32_t index{0};
    uint32_t reuse_count{0};
    uint32_t tag{0};
};

enum class thread_role_type : uint32_t
{
    ROLE_NOT_SET = 0,
    MONITOR_IPV4,
    MONITOR_IPV6
};

// Context for each test thread. This is a superset and field usage varies by test.
struct thread_context
{
    std::string program_name{};
    std::string file_name{};
    bool is_native_program{};
    std::string map_name{};
    thread_role_type role{};
    uint32_t thread_index{};
    uint32_t compartment_id{};
    uint32_t duration_minutes{};
    bool extension_restart_enabled{};
    fd_t map_fd;
    fd_t program_fd;
    std::vector<object_table_entry>& object_table;
    std::string extension_name{};
    bool succeeded{true};
};

// This call is called by the common test initialization code to get a list of programs supported by the user mode
// or kernel mode test suites. (For example, some programs could be meant for kernel mode stress testing only.)
const std::vector<std::string>
query_supported_program_names()
{
    std::vector<std::string> program_names{};

    for (const auto& program_info : _test_program_info) {
        program_names.push_back(program_info.first);
    }

    return program_names;
}

// This function is called by the common test initialization code to perform the requisite clean-up as the last action
// prior to process termination.
void
test_process_cleanup()
{
    // As of now, we don't need to do anything here for kernel mode tests.
}

// Test thread control parameters (# of threads, run duration etc.).
static test_control_info _global_test_control_info{0};

static std::once_flag _km_test_init_done;
static void
_km_test_init()
{
    std::call_once(_km_test_init_done, [&]() {
        _global_test_control_info = get_test_control_info();
        if (_global_test_control_info.programs.size()) {

            // Paranoia check - ensure that the program(s) we got back is/are indeed from our supported list.
            for (const auto& program : _global_test_control_info.programs) {
                if (std::find(
                        _global_test_control_info.programs.begin(),
                        _global_test_control_info.programs.end(),
                        program) == _global_test_control_info.programs.end()) {
                    LOG_ERROR("ERROR: Uexpected program: {}", program);
                    REQUIRE(0);
                }
            }
        } else {

            // No programs specified on the command line, so use the preferred default.
            _global_test_control_info.programs.push_back({"cgroup_sock_addr"});
        }
    });

    // Detach all programs.
    // Enumerate all link objects and detach them.
    uint32_t link_id = 0;
    while (bpf_link_get_next_id(link_id, &link_id) == 0) {
        fd_t link_fd = bpf_link_get_fd_by_id(link_id);
        if (link_fd < 0) {
            continue;
        }
        bpf_link_detach(link_fd);
        _close(link_fd);
    }
}

enum class service_state_type : uint32_t
{
    STOP,
    START
};

static bool
_set_extension_state(SC_HANDLE service_handle, service_state_type service_state, uint32_t timeout)
{
    std::string ss = (service_state == service_state_type::STOP ? "STOP" : "START");
    using sc = std::chrono::steady_clock;
    auto endtime = sc::now() + std::chrono::seconds(timeout);
    while (sc::now() < endtime) {

        LOG_VERBOSE("--> Requested state: {}", ss.c_str());
        LOG_VERBOSE("Querying driver state...");
        SERVICE_STATUS_PROCESS service_status_process{};
        uint32_t bytes_needed{};
        if (!QueryServiceStatusEx(
                service_handle,
                SC_STATUS_PROCESS_INFO,
                (uint8_t*)&service_status_process,
                sizeof(SERVICE_STATUS_PROCESS),
                (unsigned long*)&bytes_needed)) {
            LOG_ERROR("FATAL_ERROR. Polled QueryServiceStatusEx({}) failed. Error: {}", ss.c_str(), GetLastError());
            return false;
        }

        if (service_state == service_state_type::STOP) {
            if (service_status_process.dwCurrentState == SERVICE_STOPPED) {
                LOG_VERBOSE("extension STOPPED");
                return true;
            }

            // If the service is in the process of stopping, sleep for a bit before checking again.
            if (service_status_process.dwCurrentState == SERVICE_STOP_PENDING) {
                std::this_thread::sleep_for(std::chrono::milliseconds(250));
                LOG_VERBOSE("extension STOP pending");
                continue;
            }

            // Service is not in the expected state(s) so (re)send a stop code to the service.
            LOG_VERBOSE("Issuing extension STOP...");
            SERVICE_STATUS service_status{};

            // We ignore the return status here as this API returns an error if the driver is actually stopping or
            // already in a stopped state which is basically a no-op for us. This can happen if the driver goes into a
            // 'stopping/stopped' state _after_ the QueryServiceStatusEx above returns.
            (void)ControlService(service_handle, SERVICE_CONTROL_STOP, &service_status);
            LOG_VERBOSE("Issued extension STOP");

            // Sleep for a bit to let the SCM process our command.
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
            continue;
        }

        // If we get here, we're trying to start the extension.
        if (service_status_process.dwCurrentState == SERVICE_RUNNING) {
            LOG_VERBOSE("extension RUNNING");
            return true;
        }

        // If the service is in the process of starting, sleep for a bit before checking again.
        if (service_status_process.dwCurrentState == SERVICE_START_PENDING) {
            LOG_VERBOSE("extension START pending");
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
            continue;
        }

        // Service is not in the expected state(s) so attempt to (re)start the service.
        LOG_VERBOSE("Issuing extension START...");

        // We ignore the return status here as this API returns an error if the driver is actually starting or is
        // already running which is a no-op for us. This can happen if the driver goes into a 'start pending/running'
        // state _after_ the QueryServiceStatusEx above returns.
        (void)system("net start NetEbpfExt >NUL 2>&1");
        LOG_VERBOSE("Issued extension START");

        // Sleep for a bit to let the SCM process our command.
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
    return true;
}

static bool
_restart_extension(const std::string& extension_name, uint32_t timeout)
{
    bool status{false};
    SC_HANDLE scm_handle = nullptr;
    SC_HANDLE service_handle = nullptr;

    if (extension_name.size() == 0) {
        LOG_ERROR("FATAL ERROR: Extension name is empty.");
        return false;
    }

    // Get a handle to the SCM database.
    scm_handle = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (scm_handle == nullptr) {
        LOG_ERROR("FATAL ERROR: OpenSCManager failed. Error: {}", GetLastError());
        return false;
    }

    // Get a handle to the extension.
    std::wstring ws_extension_name(extension_name.begin(), extension_name.end());
    service_handle = OpenService(
        scm_handle, ws_extension_name.c_str(), (SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS));
    if (service_handle == nullptr) {
        LOG_ERROR("FATAL ERROR: OpenService failed. Service:{}, Error: {}", extension_name, GetLastError());
        CloseServiceHandle(scm_handle);
        status = false;
        goto exit;
    }

    // Toggle extension state (stop and restart).
    if (_set_extension_state(service_handle, service_state_type::STOP, timeout)) {
        if (_set_extension_state(service_handle, service_state_type::START, timeout)) {
            status = true;
            goto exit;
        }
    }

exit:
    if (!status) {
        LOG_ERROR("FATAL ERROR: Failed to restart extension: {}", extension_name.c_str());
    }

    if (service_handle != nullptr) {
        CloseServiceHandle(service_handle);
    }

    if (scm_handle != nullptr) {
        CloseServiceHandle(scm_handle);
    }

    return status;
}

static std::thread
_start_extension_restart_thread(
    thread_context& context,
    const std::string& extension_name,
    uint32_t restart_delay_ms,
    uint32_t thread_lifetime_minutes)
{
    return std::thread(
        [&](uint32_t local_restart_delay_ms, uint32_t local_thread_lifetime_minutes) {
            // Delay the start of this thread for a bit to allow the ebpf programs to attach successfully. There's a
            // window where if the extension is unloading/unloaded, an incoming attach might fail.
            std::this_thread::sleep_for(std::chrono::seconds(3));

            // Bump up the priority of this thread so it doesn't get bogged down by the test threads.
            if (!SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST)) {
                auto error = GetLastError();
                LOG_WARN(
                    "WARNING:{} - Failed to increase 'extension restart' thread priority. Error: {}", __func__, error);
            }

            using sc = std::chrono::steady_clock;
            auto endtime = sc::now() + std::chrono::minutes(local_thread_lifetime_minutes);
            while (sc::now() < endtime) {

                // Drivers can sometimes take some time to stop and (re)start and we need to poll until we can determine
                // the final status. 10 (ten) seconds seems a reasonable time for this polling.
                constexpr uint32_t RESTART_TIMEOUT_SECONDS = 10;
                LOG_VERBOSE("Toggling extension state for {} extension...", extension_name);
                if (!_restart_extension(extension_name, RESTART_TIMEOUT_SECONDS)) {
                    LOG_ERROR("FATAL ERROR: Failed to restart extension: {}", extension_name);
                    context.succeeded = false;
                }

                LOG_VERBOSE(
                    "Next restart for {} extension after a delay of {} ms", extension_name, local_restart_delay_ms);
                std::this_thread::sleep_for(std::chrono::milliseconds(local_restart_delay_ms));
            }
            LOG_INFO("**** Extension restart thread done. Exiting. ****");
        },
        restart_delay_ms,
        thread_lifetime_minutes);
}

static std::string
_generate_random_string()
{
    size_t string_length = 10;
    const std::string characters = "0123456789abcdefghijklmnopqrstuvwxyz";

    std::string random_string;
    random_string.reserve(string_length);
    for (size_t i = 0; i < string_length; ++i) {
        random_string += characters[rand() % characters.size()];
    }

    return random_string;
}

static std::string
_get_unique_file_name(const std::string& file_name)
{
    // Generate the new (unique) file name.
    std::filesystem::path file_spec = file_name;
    return (file_spec.stem().string() + "_" + _generate_random_string() + file_spec.extension().string());
}

static _Must_inspect_result_ std::string
_make_unique_file_copy(const std::string& file_name)
{
    uint32_t max_retries = 10;
    while (max_retries--) {
        try {
            std::string new_file_name = _get_unique_file_name(file_name);
            bool result =
                std::filesystem::copy_file(file_name, new_file_name, std::filesystem::copy_options::overwrite_existing);
            if (result) {
                LOG_VERBOSE("Copied {} to {}", file_name, new_file_name);
                return new_file_name;
            } else {
                LOG_ERROR("Failed to copy {} to {}", file_name, new_file_name);
                if (max_retries == 0) {
                    LOG_ERROR("Max retries exceeded.");
                    break;
                }
            }
        } catch (...) {
            LOG_ERROR("Exception caught while copying {} to a unique file name.", file_name);
            if (max_retries == 0) {
                LOG_ERROR("Max retries exceeded.");
                break;
            }
        }
    }

    LOG_ERROR("Failed to copy {} to a unique file name.", file_name);
    REQUIRE(0);
    return "";
}

static void
configure_extension_restart(
    const test_control_info& test_control_info,
    const std::vector<std::string>& extension_names,
    std::vector<std::thread>& extension_restart_thread_table,
    std::vector<thread_context>& extension_restart_thread_context_table,
    std::vector<object_table_entry>& object_table)
{
    for (uint32_t i = 0; i < extension_names.size(); i++) {
        thread_context context_entry = {
            {}, {}, false, {}, thread_role_type::ROLE_NOT_SET, 0, 0, 0, false, 0, 0, object_table};
        context_entry.extension_name = extension_names[i];
        extension_restart_thread_context_table.emplace_back(std::move(context_entry));

        extension_restart_thread_table.emplace_back(std::move(_start_extension_restart_thread(
            std::ref(extension_restart_thread_context_table.back()),
            extension_names[i],
            test_control_info.extension_restart_delay_ms,
            test_control_info.duration_minutes)));
    }
}

static void
wait_and_verify_test_threads(
    const test_control_info& test_control_info,
    std::vector<std::thread>& thread_table,
    std::vector<thread_context>& thread_context_table,
    std::vector<std::thread>& extension_restart_thread_table,
    std::vector<thread_context>& extension_restart_thread_context_table)
{
    // Wait for all test threads.
    LOG_VERBOSE("waiting on {} test threads...", thread_table.size());
    for (auto& t : thread_table) {
        t.join();
    }

    // Wait for all extension restart threads.
    if (test_control_info.extension_restart_enabled) {
        LOG_VERBOSE("waiting on {} extension restart threads...", extension_restart_thread_table.size());
        for (auto& t : extension_restart_thread_table) {
            t.join();
        }
    }

    // Check if all test threads succeeded.
    for (const auto& context : thread_context_table) {
        if (!context.succeeded) {
            LOG_ERROR(
                "FATAL ERROR: Test thread failed. role: {}, index: {}", (uint32_t)context.role, context.thread_index);
            REQUIRE(context.succeeded == true);
        }
    }

    // Check if all extension restart threads succeeded.
    if (test_control_info.extension_restart_enabled) {
        for (const auto& context : extension_restart_thread_context_table) {
            if (!context.succeeded) {
                LOG_ERROR("FATAL ERROR: Extension restart thread failed. Extension: {},", context.extension_name);
                REQUIRE(context.succeeded == true);
            }
        }
    }
}

static std::pair<bpf_object_ptr, fd_t>
_load_attach_program(thread_context& context, enum bpf_attach_type attach_type)
{
    bpf_object_ptr object_ptr;
    bpf_object* object_raw_ptr = nullptr;
    const std::string& file_name = context.file_name;
    const uint32_t thread_index = context.thread_index;

    // Get the 'object' ptr for the program associated with this thread.
    object_raw_ptr = bpf_object__open(file_name.c_str());
    if (object_raw_ptr == nullptr) {
        LOG_ERROR(
            "{}({}) FATAL ERROR: bpf_object__open({}) failed. errno:{}",
            __func__,
            thread_index,
            file_name.c_str(),
            errno);
        context.succeeded = false;
        return {};
    }
    LOG_VERBOSE("{}({}) Opened file:{}", __func__, thread_index, file_name.c_str());

    // Load the program.
    auto result = bpf_object__load(object_raw_ptr);
    if (result != 0) {
        LOG_ERROR(
            "{}({}) FATAL ERROR: bpf_object__load({}) failed. result:{}, errno:{}",
            __func__,
            thread_index,
            file_name.c_str(),
            result,
            errno);
        context.succeeded = false;
        return {};
    }
    object_ptr.reset(object_raw_ptr);
    LOG_VERBOSE("{}({}) loaded file:{}", __func__, thread_index, file_name.c_str());

    // Get program object for the (only) program in this file.
    auto program = bpf_object__next_program(object_raw_ptr, nullptr);
    if (program == nullptr) {
        LOG_ERROR(
            "{}({}) FATAL ERROR: bpf_object__next_program({}) failed. errno:{}",
            __func__,
            thread_index,
            file_name.c_str(),
            errno);
        context.succeeded = false;
        return {};
    }
    LOG_VERBOSE(
        "{}({}) Found program object for program:{}, file_name:{}",
        __func__,
        thread_index,
        program->program_name,
        file_name.c_str());

    // Get the fd for this program.
    fd_t program_fd = bpf_program__fd(program);
    if (program_fd < 0) {
        LOG_ERROR(
            "{}({}) FATAL ERROR: bpf_program__fd({}) failed. program:{}, errno:{}",
            __func__,
            thread_index,
            file_name.c_str(),
            program->program_name,
            errno);
        context.succeeded = false;
        return {};
    }
    LOG_VERBOSE(
        "{}({}) Opened fd:{}, for program:{}, file_name:{}",
        __func__,
        thread_index,
        program_fd,
        program->program_name,
        file_name.c_str());

    // Enforce the 'unspecified' compartment id. In the absence of additional compartments in the system, (as of now)
    // a non-existent id causes a kernel assert in netebpfext.sys debug builds.
    result = bpf_prog_attach(program_fd, UNSPECIFIED_COMPARTMENT_ID, attach_type, 0);
    if (result != 0) {
        LOG_ERROR(
            "{}({}) FATAL ERROR: bpf_prog_attach({}) failed. program:{}, errno:{}",
            __func__,
            thread_index,
            file_name.c_str(),
            program->program_name,
            errno);
        context.succeeded = false;
        return {};
    }
    LOG_VERBOSE(
        "{}({}) Attached program:{}, file_name:{}", __func__, thread_index, program->program_name, file_name.c_str());

    return std::make_pair(std::move(object_ptr), program_fd);
}

static void
_invoke_mt_sockaddr_thread_function(thread_context& context)
{
    SOCKET socket_handle;
    SOCKADDR_STORAGE remote_endpoint{};

    if (context.role == thread_role_type::MONITOR_IPV4) {
        socket_handle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        remote_endpoint.ss_family = AF_INET;
    } else {
        socket_handle = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        remote_endpoint.ss_family = AF_INET6;
    }
    if (socket_handle == INVALID_SOCKET) {
        LOG_ERROR("{}({}) - FATAL ERROR: socket() failed. errno:{}", __func__, context.thread_index, WSAGetLastError());
        context.succeeded = false;
        exit(-1);
    }
    INETADDR_SETLOOPBACK(reinterpret_cast<PSOCKADDR>(&remote_endpoint));
    uint16_t remote_port = SOCKET_TEST_PORT + static_cast<uint16_t>(context.thread_index);
    (reinterpret_cast<PSOCKADDR_IN>(&remote_endpoint))->sin_port = htons(remote_port);

    using sc = std::chrono::steady_clock;
    auto endtime = sc::now() + std::chrono::minutes(context.duration_minutes);
    while (sc::now() < endtime) {

        // Now send out a small burst of TCP 'connect' attempts for the duration of the test.  We do this to increase
        // the probability of a collision between the program invocation and the extension being restarted at the same
        // time.
        // Note: The burst size needs to be small as larger bursts seem to cause inordinately large delays in returning
        // from the connect call (for the PROCEED and REDIRECT cases).
        constexpr uint32_t BURST_SIZE = 4;
        LOG_VERBOSE("Thread[{}] - connecting to port:{}", context.thread_index, remote_port);
        for (uint32_t i = 0; i < BURST_SIZE; i++) {

            // We just want to ensure that our program gets invoked, so we don't care if 'connect' fails.
            (void)connect(
                socket_handle,
                reinterpret_cast<SOCKADDR*>(&remote_endpoint),
                static_cast<int>(sizeof(remote_endpoint)));
        }
        LOG_VERBOSE("Thread[{}] connect done to port:{}", context.thread_index, remote_port);
    }
    LOG_VERBOSE("Thread[{}] Done.", context.thread_index);
}

static void
_mt_sockaddr_invoke_program_test(ebpf_execution_type_t program_type, const test_control_info& test_control_info)
{
    WSAData data{};
    auto error = WSAStartup(MAKEWORD(2, 2), &data);
    REQUIRE(error == 0);

    // Choose file extension based on execution type.
    bool is_native = (program_type == EBPF_EXECUTION_NATIVE);
    // The VS2026 Code Analysis engine newly flags this pre-existing call (VS2022 did not): _make_unique_file_copy()
    // is _Must_inspect_result_, and on failure it returns an empty string. That empty string makes the subsequent
    // program load fail the REQUIRE check below, so explicit inspection of the result here is unnecessary.
#pragma warning(suppress : 28193) // 'file_name' holds a value that must be examined.
    std::string file_name = is_native ? _make_unique_file_copy("cgroup_mt_connect6.sys") : "cgroup_mt_connect6.o";

    std::vector<object_table_entry> dummy_table(1);
    thread_context program_load_context = {
        {}, {}, false, {}, thread_role_type::ROLE_NOT_SET, 0, 0, 0, false, 0, 0, dummy_table};
    program_load_context.file_name = file_name;
    program_load_context.thread_index = 0;
    auto [program_object, _] = _load_attach_program(program_load_context, BPF_CGROUP_INET6_CONNECT);
    REQUIRE(program_load_context.succeeded == true);

    size_t total_threads = test_control_info.threads_count;
    std::vector<thread_context> thread_context_table(
        total_threads, {{}, {}, false, {}, thread_role_type::ROLE_NOT_SET, 0, 0, 0, false, 0, 0, dummy_table});
    std::vector<std::thread> test_thread_table(total_threads);
    for (uint32_t i = 0; i < total_threads; i++) {

        // First, prepare the context for this thread.
        auto& context_entry = thread_context_table[i];
        context_entry.is_native_program = is_native;
        context_entry.role = thread_role_type::MONITOR_IPV6;
        context_entry.thread_index = i;
        context_entry.duration_minutes = test_control_info.duration_minutes;
        context_entry.extension_restart_enabled = test_control_info.extension_restart_enabled;

        // Now create the thread.
        auto& thread_entry = test_thread_table[i];
        thread_entry = std::move(std::thread(_invoke_mt_sockaddr_thread_function, std::ref(context_entry)));
    }

    // Another table for the 'extension restart' threads.
    std::vector<std::string> extension_names = {"netebpfext"};
    std::vector<std::thread> extension_restart_thread_table{};
    std::vector<thread_context> extension_restart_thread_context_table{};

    if (test_control_info.extension_restart_enabled) {
        configure_extension_restart(
            test_control_info,
            extension_names,
            extension_restart_thread_table,
            extension_restart_thread_context_table,
            dummy_table);
    }

    wait_and_verify_test_threads(
        test_control_info,
        test_thread_table,
        thread_context_table,
        extension_restart_thread_table,
        extension_restart_thread_context_table);
}

static void
_print_test_control_info(const test_control_info& test_control_info)
{
    uint32_t resolved_thread_count = test_control_info.threads_count;
    if (resolved_thread_count == 0) {
        resolved_thread_count = default_km_invoke_thread_count();
    }
    if (resolved_thread_count != 0) {
        LOG_INFO("test thread count          : {}", resolved_thread_count);
    }
    LOG_INFO("test duration (in minutes)  : {}", test_control_info.duration_minutes);
    LOG_INFO("test verbose output         : {}", test_control_info.verbose_output);
    LOG_INFO("test extension restart      : {}", test_control_info.extension_restart_enabled);
    if (test_control_info.extension_restart_enabled) {
        LOG_INFO("test extension restart delay: {} ms", test_control_info.extension_restart_delay_ms);
    }
}

static void
_set_up_tailcall_program(bpf_object* object, const std::string& map_name)
{
    REQUIRE(object != nullptr);

    fd_t prog_map_fd = bpf_object__find_map_fd_by_name(object, map_name.c_str());
    if (prog_map_fd < 0) {
        LOG_ERROR(
            "({}) FATAL ERROR: bpf_object__find_map_fd_by_name({}) failed. Errno:{}",
            __func__,
            map_name.c_str(),
            errno);
        REQUIRE(prog_map_fd >= 0);
    }
    LOG_VERBOSE("({}) Opened fd:{} for map:{}", __func__, prog_map_fd, map_name.c_str());

    // Set up tail calls.
    for (int index = 0; index < MAX_TAIL_CALL_CNT; index++) {
        try {
            std::string bind_program_name{"BindMonitor_Callee"};
            bind_program_name += std::to_string(index);

            // Try to get a handle to the 'BindMonitor_Callee<index>' program.
            bpf_program* callee = bpf_object__find_program_by_name(object, bind_program_name.c_str());

            if (callee == nullptr) {
                LOG_ERROR("({}) - bpf_object__find_program_by_name() failed. errno: {}", bind_program_name, errno);
                REQUIRE(callee != nullptr);
            }
            LOG_VERBOSE("({}) - bpf_object__find_program_by_name() success.", bind_program_name);

            fd_t callee_fd = bpf_program__fd(callee);
            if (callee_fd < 0) {
                LOG_ERROR("({}) - bpf_program__fd() failed. errno: {}", bind_program_name, errno);
                REQUIRE(callee_fd > 0);
            }
            LOG_VERBOSE("({}) - bpf_program__fd() for callee_fd:{} success.", bind_program_name, callee_fd);

            uint32_t result = bpf_map_update_elem(prog_map_fd, &index, &callee_fd, 0);
            if (result < 0) {
                LOG_ERROR("({}) - bpf_map_update_elem() failed. errno: {}", bind_program_name, errno);
                REQUIRE(result == ERROR_SUCCESS);
            }
            LOG_VERBOSE("({}) - bpf_map_update_elem() for callee_fd:{} success.", bind_program_name, callee_fd);

        } catch (...) {
            // No need to terminate. We don't care about user mode issues here.
        }
    }
}

static void
_invoke_mt_bindmonitor_tail_call_thread_function(thread_context& context)
{
    // Test bind.
    SOCKET socket_handle = INVALID_SOCKET;
    SOCKADDR_STORAGE remote_endpoint{};

    if (context.role == thread_role_type::MONITOR_IPV4) {
        remote_endpoint.ss_family = AF_INET;
    } else {
        ASSERT(context.role == thread_role_type::MONITOR_IPV6);
        remote_endpoint.ss_family = AF_INET6;
    }

    uint16_t remote_port = SOCKET_TEST_PORT + static_cast<uint16_t>(context.thread_index);
    using sc = std::chrono::steady_clock;
    auto endtime = sc::now() + std::chrono::minutes(context.duration_minutes);
    while (sc::now() < endtime) {

        // Now send out a small burst of TCP 'bind' attempts for the duration of the test.  We do this to increase
        // the probability of a collision between the program invocation and the extension being restarted at the same
        // time.
        constexpr uint32_t BURST_SIZE = 5;
        int result = 0;

        for (uint32_t i = 0; i < BURST_SIZE; i++) {
            // Create a socket.
            socket_handle = WSASocket(remote_endpoint.ss_family, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, 0);
            if (socket_handle == INVALID_SOCKET) {
                LOG_ERROR("Thread[{}] WSASocket() failed. errno:{}", context.thread_index, WSAGetLastError());
                context.succeeded = false;
                exit(-1);
            }

            INETADDR_SETANY(reinterpret_cast<PSOCKADDR>(&remote_endpoint));
            SS_PORT(&remote_endpoint) = htons(remote_port);

            // Forcefully bind to the same port in use using socket option SO_REUSEADDR.
            // One of the use-case: multicast sockets.
            const char optval = 1;
            result = setsockopt(socket_handle, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
            if (result != 0) {
                LOG_ERROR(
                    "Thread[{}] setsockopt result:{} {} to port:{}",
                    context.thread_index,
                    result,
                    WSAGetLastError(),
                    remote_port);
                closesocket(socket_handle);
                context.succeeded = false;
                exit(-1);
            }

            // Bind the socket.
            LOG_VERBOSE("Thread[{}] - binding to port:{}", context.thread_index, remote_port);
            result = bind(socket_handle, (PSOCKADDR)&remote_endpoint, sizeof(remote_endpoint));
            if (result != 0) {
                LOG_ERROR(
                    "Thread[{}] bind result:{} {} to port:{}",
                    context.thread_index,
                    result,
                    WSAGetLastError(),
                    remote_port);
                closesocket(socket_handle);
                context.succeeded = false;
                exit(-1);
            }

            LOG_VERBOSE("Thread[{}] bind success to port:{}", context.thread_index, remote_port);
            closesocket(socket_handle);
        }
    }
    LOG_VERBOSE("Thread[{}] Done.", context.thread_index);
}

static std::pair<bpf_object_ptr, fd_t>
_load_attach_tail_program(thread_context& context, ebpf_attach_type_t attach_type, bpf_prog_type program_type)
{
    bpf_object_ptr object_ptr;
    bpf_object* object_raw_ptr = nullptr;
    bpf_link* link = nullptr;
    const std::string& file_name = context.file_name;
    const std::string& program_name = context.program_name;
    const uint32_t thread_index = context.thread_index;

    // Get the 'object' ptr for the program associated with this thread.
    object_raw_ptr = bpf_object__open(file_name.c_str());
    if (object_raw_ptr == nullptr) {
        LOG_ERROR(
            "{}({}) FATAL ERROR: bpf_object__open({}) failed. errno:{}",
            __func__,
            thread_index,
            file_name.c_str(),
            errno);
        context.succeeded = false;
        exit(-1);
    }
    LOG_VERBOSE("{}({}) Opened file:{}", __func__, thread_index, file_name.c_str());

    // Load the program.
    auto result = bpf_object__load(object_raw_ptr);
    if (result != 0) {
        LOG_ERROR(
            "{}({}) FATAL ERROR: bpf_object__load({}) failed. errno:{}",
            __func__,
            thread_index,
            file_name.c_str(),
            errno);
        context.succeeded = false;
        exit(-1);
    }
    object_ptr.reset(object_raw_ptr);
    LOG_VERBOSE("{}({}) loaded file:{}", __func__, thread_index, file_name.c_str());

    // Load program by name.
    bpf_program* program = bpf_object__find_program_by_name(object_raw_ptr, program_name.c_str());
    if (program == nullptr) {
        LOG_ERROR(
            "{}({}) FATAL ERROR: bpf_object__find_program_by_name({}) failed. errno:{}",
            __func__,
            thread_index,
            file_name.c_str(),
            errno);
        context.succeeded = false;
        exit(-1);
    }
    LOG_VERBOSE(
        "{}({}) Found program object for program:{}, file_name:{}",
        __func__,
        thread_index,
        program->program_name,
        file_name.c_str());

    // Set the program type.
    bpf_program__set_type(program, program_type);

    // Get the fd for this program.
    fd_t program_fd = bpf_program__fd(program);
    if (program_fd < 0) {
        LOG_ERROR(
            "{}({}) FATAL ERROR: bpf_program__fd({}) failed. program:{}, errno:{}",
            __func__,
            thread_index,
            file_name.c_str(),
            program->program_name,
            errno);
        context.succeeded = false;
        exit(-1);
    }
    LOG_VERBOSE(
        "{}({}) Opened fd:{}, for program:{}, file_name:{}",
        __func__,
        thread_index,
        program_fd,
        program->program_name,
        file_name.c_str());

    result = ebpf_program_attach(program, &attach_type, nullptr, 0, &link);
    if (result != ERROR_SUCCESS) {
        LOG_ERROR(
            "{}({}) FATAL ERROR: bpf_prog_attach({}) failed. program:{}, errno:{}",
            __func__,
            thread_index,
            file_name.c_str(),
            program->program_name,
            errno);
        context.succeeded = false;
        exit(-1);
    }
    LOG_VERBOSE(
        "{}({}) Attached program:{}, file_name:{}", __func__, thread_index, program->program_name, file_name.c_str());

    return std::make_pair(std::move(object_ptr), program_fd);
}

static void
_mt_bindmonitor_tail_call_invoke_program_test(
    ebpf_execution_type_t program_type, const test_control_info& test_control_info)
{
    WSAData data{};
    auto error = WSAStartup(MAKEWORD(2, 2), &data);
    REQUIRE(error == 0);

    // Choose file extension based on execution type.
    bool is_native = (program_type == EBPF_EXECUTION_NATIVE);
    // The VS2026 Code Analysis engine newly flags this pre-existing call (VS2022 did not): _make_unique_file_copy()
    // is _Must_inspect_result_, and on failure it returns an empty string. That empty string makes the subsequent
    // program load fail the REQUIRE check below, so explicit inspection of the result here is unnecessary.
#pragma warning(suppress : 28193) // 'file_name' holds a value that must be examined.
    std::string file_name =
        is_native ? _make_unique_file_copy("bindmonitor_mt_tailcall.sys") : "bindmonitor_mt_tailcall.o";

    // Load the program.
    std::vector<object_table_entry> dummy_table(1);
    thread_context program_load_context = {
        {}, {}, false, {}, thread_role_type::ROLE_NOT_SET, 0, 0, 0, false, 0, 0, dummy_table};
    program_load_context.program_name = "BindMonitor_Caller";
    program_load_context.file_name = file_name;
    program_load_context.map_name = "bind_tail_call_map";
    program_load_context.thread_index = 0;
    auto [program_object, _] =
        _load_attach_tail_program(program_load_context, EBPF_ATTACH_TYPE_BIND, BPF_PROG_TYPE_BIND);
    REQUIRE(program_load_context.succeeded == true);

    // Set up the tail call programs.
    _set_up_tailcall_program(program_object.get(), program_load_context.map_name);

    // Needed for thread_context initialization.
    constexpr uint32_t MAX_BIND_PROGRAM = 1;

    // Storage for object pointers for each ebpf program file opened by bpf_object__open().
    std::vector<object_table_entry> object_table(MAX_BIND_PROGRAM);
    for (uint32_t index = 0; auto& entry : object_table) {
        entry.available = true;
        entry.lock = std::make_unique<std::mutex>();
        entry.object = std::move(program_object);
        entry.attach = !(index % 2) ? true : false;
        entry.index = index++;
        entry.reuse_count = 0;
        entry.tag = 0xC001DEA2;
    }

    size_t total_threads = test_control_info.threads_count;
    std::vector<thread_context> thread_context_table(
        total_threads, {{}, {}, false, {}, thread_role_type::ROLE_NOT_SET, 0, 0, 0, false, 0, 0, object_table});
    std::vector<std::thread> test_thread_table(total_threads);
    for (uint32_t i = 0; i < total_threads; i++) {

        // First, prepare the context for this thread.
        auto& context_entry = thread_context_table[i];
        context_entry.is_native_program = is_native;
        context_entry.role = thread_role_type::MONITOR_IPV6;
        context_entry.thread_index = i;
        context_entry.duration_minutes = test_control_info.duration_minutes;
        context_entry.extension_restart_enabled = test_control_info.extension_restart_enabled;

        // Now create the thread.
        auto& thread_entry = test_thread_table[i];
        thread_entry =
            std::move(std::thread(_invoke_mt_bindmonitor_tail_call_thread_function, std::ref(context_entry)));
    }

    // If requested, start the 'extension stop-and-restart' thread for extension for this program type.
    std::vector<std::string> extension_names = {"netebpfext"};
    std::vector<std::thread> extension_restart_thread_table;
    std::vector<thread_context> extension_restart_thread_context_table;
    if (test_control_info.extension_restart_enabled) {
        configure_extension_restart(
            test_control_info,
            extension_names,
            extension_restart_thread_table,
            extension_restart_thread_context_table,
            object_table);
    }

    wait_and_verify_test_threads(
        test_control_info,
        test_thread_table,
        thread_context_table,
        extension_restart_thread_table,
        extension_restart_thread_context_table);

    // Clean up Winsock.
    WSACleanup();
}

TEST_CASE("sockaddr_invoke_program_test", "[native_mt_stress_test]")
{
    // Test layout:
    // 1. Load the "cgroup_mt_connect6.sys" native ebpf program.
    //    - This program monitors an IPv6 endpoint, [::1]:<target_port>. On every invocation, the program returns a
    //      specific value per the following (arbitrary) algorithm:
    //      > (target_port % 3 == 0) : BPF_SOCK_ADDR_VERDICT_REJECT
    //        (target_port % 2 == 0) : BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT
    //        else                   : BPF_SOCK_ADDR_VERDICT_REDIRECT
    //
    // 2. Create the specified # of threads and for the duration of test, each thread will:
    //    - Attempt a TCP 'connect' to the remote endpoint [::1]:<target_port + thread_context.thread_index>
    //      continuously in a loop.
    //      (The test set up ensures that the thread_index passed in each thread_context is unique to that thread.)
    //
    //    We ignore the result of the 'connect' attempt as the intent here is to test the parallel invocation of the
    //    WFP callout and ensure this test doesn't cause kernel mode crashes.
    //
    // 3. If specified, start the 'extension restart' thread as well to continuously restart the netebpf extension.

    _km_test_init();
    LOG_INFO("\nStarting test *** sockaddr_invoke_program_test ***");
    test_control_info local_test_control_info = _global_test_control_info;
    if (local_test_control_info.threads_count == 0) {
        local_test_control_info.threads_count = DEFAULT_KM_NATIVE_MT_THREAD_COUNT;
    }
    if (local_test_control_info.duration_minutes == 0) {
        local_test_control_info.duration_minutes = DEFAULT_KM_NATIVE_MT_DURATION_MINUTES;
    }

    _print_test_control_info(local_test_control_info);
    _mt_sockaddr_invoke_program_test(EBPF_EXECUTION_NATIVE, local_test_control_info);
}

TEST_CASE("bindmonitor_tail_call_invoke_program_test", "[native_mt_stress_test]")
{
    // Test layout:
    // 1. Load the "bindmonitor_mt_tailcall.sys" native ebpf program.
    // 2. Load MAX_TAIL_CALL_CNT tail call programs.
    // 3. Create the specified number of threads.
    //   - Each thread will invoke the TCP 'bind'.
    //   - This will invoke MAX_TAIL_CALL_CNT tail call programs for permit.

    _km_test_init();
    LOG_INFO("\nStarting test *** bindmonitor_tailcall_invoke_program_test ***");
    test_control_info local_test_control_info = _global_test_control_info;
    if (local_test_control_info.threads_count == 0) {
        local_test_control_info.threads_count = DEFAULT_KM_NATIVE_MT_THREAD_COUNT;
    }
    if (local_test_control_info.duration_minutes == 0) {
        local_test_control_info.duration_minutes = DEFAULT_KM_NATIVE_MT_DURATION_MINUTES;
    }

    _print_test_control_info(local_test_control_info);
    _mt_bindmonitor_tail_call_invoke_program_test(EBPF_EXECUTION_NATIVE, local_test_control_info);
}

TEST_CASE("sample_attach_invoke_detach_race_km", "[stress_km]")
{
    _km_test_init();
    LOG_INFO("\nStarting test *** sample_attach_invoke_detach_race_km ***");

    hook_helper_t hook(EBPF_ATTACH_TYPE_SAMPLE);

    bpf_object* object = nullptr;
    bpf_program* program = nullptr;
    fd_t program_fd = -1;
    fd_t map_fd = -1;
    REQUIRE(
        sample_stress_load_program(
            "test_sample_ebpf.sys", BPF_PROG_TYPE_SAMPLE, &object, &program, &program_fd, &map_fd) == 0);
    (void)map_fd;

    auto test_control = get_test_control_info();
    uint32_t duration_minutes =
        test_control.duration_minutes == 0 ? DEFAULT_DURATION_MINUTES : test_control.duration_minutes;
    uint32_t invoke_thread_count =
        test_control.threads_count == 0 ? default_km_invoke_thread_count() : test_control.threads_count;
    uint32_t attach_detach_delay_ms =
        test_control.attach_detach_delay_ms == 0 ? DEFAULT_ATTACH_DETACH_DELAY_MS : test_control.attach_detach_delay_ms;

    std::vector<uint32_t> attach_data(invoke_thread_count);
    for (uint32_t i = 0; i < invoke_thread_count; i++) {
        attach_data[i] = i;
        REQUIRE(hook.attach(program, &attach_data[i], sizeof(attach_data[i])) != nullptr);
    }

    std::atomic<uint32_t> next_worker_id{0};
    std::atomic<uint64_t> detach_failure_count{0};
    std::atomic<uint64_t> attach_failure_count{0};
    auto invoke_routine = [&]() {
        thread_local const uint32_t worker_id = next_worker_id.fetch_add(1);
        thread_local _sample_extension_helper invoke_extension(false);
        thread_local std::vector<char> input_buffer = {'r', 'a', 'i', 'n', 'y'};
        thread_local std::vector<char> output_buffer(256);
        uint32_t attach_value = attach_data[worker_id % invoke_thread_count];
        (void)invoke_extension.try_invoke_by_attach_parameter(
            &attach_value, sizeof(attach_value), input_buffer, output_buffer);
    };
    auto detach_routine = [&]() {
        for (uint32_t i = 0; i < invoke_thread_count; i++) {
            if (hook.detach(program_fd, &attach_data[i], sizeof(attach_data[i])) != EBPF_SUCCESS) {
                ++detach_failure_count;
            }
        }
    };
    auto attach_routine = [&]() {
        for (uint32_t i = 0; i < invoke_thread_count; i++) {
            if (hook.attach(program, &attach_data[i], sizeof(attach_data[i])) == nullptr) {
                ++attach_failure_count;
            }
        }
    };

    run_attach_invoke_detach_race(
        invoke_routine, detach_routine, attach_routine, duration_minutes, invoke_thread_count, attach_detach_delay_ms);
    LOG_INFO(
        "Race attach/detach failures: detach_failures={}, attach_failures={}",
        detach_failure_count.load(),
        attach_failure_count.load());

    for (uint32_t i = 0; i < invoke_thread_count; i++) {
        (void)hook.detach(program_fd, &attach_data[i], sizeof(attach_data[i]));
    }
    sample_stress_close_program(object);
}
