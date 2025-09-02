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
#include "service_helper.h"
#include "socket_helper.h"
#include "socket_tests_common.h"

// Note: The 'program' and 'execution' types are not required for km tests.
static const std::map<std::string, test_program_attributes> _test_program_info = {
    {{"cgroup_sock_addr"},
     {{"cgroup_sock_addr.o"},
      {"cgroup_sock_addr.sys"},
      {"netebpfext"},
      nullptr,
      BPF_PROG_TYPE_UNSPEC,
      EBPF_EXECUTION_ANY}}};

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

// Possible roles for each thread. A thread is assigned a specific role at creation and it does not change thereafter.
//
// 'Creator' threads create as many ebpf program objects as they can, gated by the size of the object_table array.
//
// The 'Attacher' threads will alternatively 'attach' or 'detach' the program objects created by the 'Creator' threads
// w/o considering if the objects have already been attached or detached.  Any errors returned by the ebpfapi are
// ignored.
//
// 'Destroyer' threads close as many 'opened' eBPF program objects as then can.  These threads synchronize access to
// the object table entries with the 'Creator' and 'Attacher' threads as the destroyer threads can only destroy program
// objects that were created by the creator threads in the first place.
//
// The intent here is to cause the maximum nondeterministic multi-threaded stress scenarios as possible. Note that we
// do not care about user mode failures in, or errors returned from, ebpfapi and focus only on exercing the in-kernel
// eBPF components' ability to deal with such situations w/o causing a kernel hang or crash. The primary test goal here
// is to ensure that such races do not cause hangs or crashes in the in-kernel eBPF sub-system components
// (ebpfcore, netebpfext drivers).

enum class thread_role_type : uint32_t
{
    ROLE_NOT_SET = 0,
    CREATOR,
    ATTACHER,
    DESTROYER,
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

static void
_do_creator_work(thread_context& context, std::time_t endtime_seconds)
{
    // Wait for an entry to become available.
    for (auto& entry : context.object_table) {

        // Abort operations if we're past the test duration time quantum.
        using sc = std::chrono::system_clock;
        auto timenow = sc::now();
        std::time_t timenow_seconds = std::chrono::system_clock::to_time_t(timenow);
        if (timenow_seconds >= endtime_seconds) {
            break;
        }

        // Do an un-protected read of 'entry.available' flag to avoid an un-necessary lock if the entry _is_ in use.
        if (entry.available) {
            {
                // Note that we're deliberately splitting the lock grab between the 'open' and 'load' calls.  This is
                // to force a race between 'load', 'attach' and 'destroy'.
                std::lock_guard lock(*entry.lock.get());

                // Make sure entry is _still_ free (some other creator thread may have grabbed it)
                if (!entry.available) {
                    continue;
                }

                bpf_object* object_raw_ptr = nullptr;
                try {

                    // Load program and store returned object pointer.
                    object_raw_ptr = bpf_object__open(context.file_name.c_str());
                    if (object_raw_ptr == nullptr) {
                        if (context.extension_restart_enabled) {

                            // While this is a fatal error, we need to ignore such errors if the 'extension restart'
                            // thread is running.  Such errors are expected in that scenario especially when the
                            // extension keeps getting yanked from under us.
                            continue;
                        }

                        LOG_ERROR(
                            "(CREATOR)[{}][{}] - FATAL ERROR: bpf_object__open() failed for {}. errno: {}",
                            context.thread_index,
                            entry.index,
                            context.file_name.c_str(),
                            errno);

                        context.succeeded = false;
                        exit(-1);
                    }

                    // So far so good, so mark the entry as 'not available', i.e. we have 'opened' the ebpf program.
                    // This should now trigger a race between 'load', 'attach' and 'destroy' which should be handled
                    // in a robust manner by ebpfcore.
                    entry.object.reset(object_raw_ptr);
                    entry.reuse_count++;
                    entry.available = false;
                } catch (...) {

                    // If the 'extension restart' thread is enabled (-jre=true specified on the command line), errors
                    // in any/all of the ebpfapi calls in the above 'try' block are expected and are ignored.
                    if (context.extension_restart_enabled) {
                        continue;
                    }

                    // OTOH, if the 'extension restart' thread is _NOT_ active, these calls must always succeed and any
                    // errors/exceptions here are fatal.  In this scenario, we cannot attach (and subsequently close)
                    // program objects if they don't exist in the first place, so there's no point in letting the test
                    // continue execution.
                    LOG_ERROR(
                        "(CREATOR)[{}][{}] - FATAL ERROR: Unexpected exception caught (bpf_object__open). file: {} "
                        "errno: {}",
                        context.thread_index,
                        entry.index,
                        context.file_name.c_str(),
                        errno);
                    context.succeeded = false;
                    exit(-1);
                }
                LOG_VERBOSE("(CREATOR)[{}][{}] - Object created.", context.thread_index, entry.index);
            }

            {
                // This is the second lock grab to 'load' the program.
                std::lock_guard lock(*entry.lock.get());

                // We're racing with 'attach' _AND_ 'destroy', so make sure the object was not already destroyed
                // by the time we get here.
                if (entry.available) {
                    continue;
                }

                // Move on if the bpf program has already been loaded by some other 'creator' thread.
                if (entry.loaded) {
                    continue;
                }

                try {
                    auto result = bpf_object__load(entry.object.get());
                    if (result != 0) {
                        if (context.extension_restart_enabled) {

                            // While this is a fatal error for non-native programs (native programs are windows kernel
                            // mode drivers and the OS will not allow loading the same driver multiple times), we need
                            // to ignore such errors (for non-native programs as well) if the 'extension restart'
                            // thread is running.  Such errors are expected in that scenario especially when the
                            // extension keeps getting yanked from under us.
                            continue;
                        }

                        if (!context.is_native_program) {
                            LOG_ERROR(
                                "(CREATOR)[{}][{}] - FATAL ERROR: bpf_object__load() failed. result: {}, errno: {} "
                                "progname: {}",
                                context.thread_index,
                                entry.index,
                                result,
                                errno,
                                context.file_name.c_str());

                            context.succeeded = false;
                            exit(-1);
                        }
                    } else {
                        LOG_VERBOSE(
                            "(CREATOR)[{}][{}] - bpf_object__load() succeeded progname: {}",
                            context.thread_index,
                            entry.index,
                            context.file_name.c_str());
                    }
                } catch (...) {

                    // If the 'extension restart' thread is enabled, errors in any/all of the ebpfapi calls in the
                    // above 'try' block are expected and are ignored.
                    if (context.extension_restart_enabled) {
                        continue;
                    }

                    // OTOH, if the 'extension restart' thread is _NOT_ active, these calls must always succeed and any
                    // errors/exceptions here are fatal.  In this scenario, we cannot attach (and subsequently close)
                    // program objects if they don't exist in the first place, so there's no point in letting the test
                    // continue execution.
                    LOG_ERROR(
                        "(CREATOR)[{}][{}] - FATAL ERROR: Unexpected exception caught (bpf_object__load). errno: {} "
                        "filename: {}",
                        context.thread_index,
                        entry.index,
                        errno,
                        context.file_name.c_str());
                    context.succeeded = false;
                    exit(-1);
                }
                entry.loaded = true;
                LOG_VERBOSE(
                    "(CREATOR)[{}][{}][{}] - Object loaded.",
                    context.thread_index,
                    entry.index,
                    context.file_name.c_str());
            }
        }
    }
}

static void
_do_attacher_work(thread_context& context, std::time_t endtime_seconds)
{
    for (auto& entry : context.object_table) {

        // Abort operations if we're past the test duration time quantum.
        using sc = std::chrono::system_clock;
        auto timenow = sc::now();
        std::time_t timenow_seconds = std::chrono::system_clock::to_time_t(timenow);
        if (timenow_seconds >= endtime_seconds) {
            break;
        }

        // Do an un-protected read of 'entry.available' flag to avoid an un-necessary lock if the entry is not in use.
        if (!entry.available) {

            // Take the lock and make sure entry is _still_ in use (some other 'destroyer' may have closed this
            // object and marked this entry as 'available').
            std::lock_guard lock(*entry.lock.get());
            if (entry.available) {
                continue;
            }

            try {
                std::string connect_program_name{"authorize_connect4"};

                // Try to get a handle to the 'connect' program.
                bpf_program* connect_program =
                    bpf_object__find_program_by_name(entry.object.get(), connect_program_name.c_str());
                if (connect_program == nullptr) {

                    // This failure (and in other ebpf api calls) in this 'try' block is fine as some 'destroyer'
                    // thread may have just destroyed this object.  This should not cause any issues with the in-kernel
                    // ebpf components.
                    LOG_VERBOSE(
                        "(ATTACHER)[{}][{}] - bpf_object__find_program_by_name() failed. errno: {}",
                        context.thread_index,
                        entry.index,
                        errno);
                    continue;
                }

                auto fd = bpf_program__fd(connect_program);
                if (fd < 0) {
                    LOG_VERBOSE(
                        "(ATTACHER)[{}][{}] - bpf_program__fd() failed. errno: {}",
                        context.thread_index,
                        entry.index,
                        errno);
                    continue;
                }

                // Try to attach or detach the 'connect' program at BPF_CGROUP_INET4_CONNECT hook.
                int result{0};
                if (entry.attach) {
                    result = bpf_prog_attach(fd, context.compartment_id, BPF_CGROUP_INET4_CONNECT, 0);
                } else {
                    result = bpf_prog_detach(context.compartment_id, BPF_CGROUP_INET4_CONNECT);
                }
                if (result != 0) {
                    LOG_VERBOSE(
                        "(ATTACHER)[{}][{}] - {} failed for compartment_id: {}. errno: {}",
                        context.thread_index,
                        entry.index,
                        (entry.attach ? "bpf_prog_attach()" : "bpf_prog_detach()"),
                        context.compartment_id,
                        errno);
                } else {
                    LOG_VERBOSE(
                        "(ATTACHER)[{}][{}] - {}. compartment_id: {}.",
                        context.thread_index,
                        entry.index,
                        (entry.attach ? "Attached" : "Detached"),
                        context.compartment_id);
                }

                // Flip the next attach/detach action on this object irrespective of errors (if any) above.
                entry.attach = !entry.attach;

            } catch (...) {

                // No need to terminate. We don't care about user mode issues here.
            }
        }
    }
}

static void
_do_destroyer_work(thread_context& context, std::time_t endtime_seconds)
{
    for (auto& entry : context.object_table) {

        // Abort operations if we're past the test duration time quantum.
        using sc = std::chrono::system_clock;
        auto timenow = sc::now();
        std::time_t timenow_seconds = std::chrono::system_clock::to_time_t(timenow);
        if (timenow_seconds >= endtime_seconds) {
            break;
        }

        // Do an un-protected read of 'entry.available' flag to avoid an un-necessary lock if the entry not in use.
        if (!entry.available) {

            // Take the lock and make sure entry is _still_ in use (some other 'destroyer' may have closed this object
            // and marked this entry as 'available').
            std::lock_guard lock(*entry.lock.get());
            if (entry.available) {
                continue;
            }

            // Close the object.
            bpf_object__close(entry.object.get());
            entry.object.release();
            entry.available = true;
            entry.loaded = false;

            LOG_VERBOSE(
                "(DESTROYER)[{}][{}] - Destroyed. comparment_id: {}",
                context.thread_index,
                entry.index,
                context.compartment_id);
        }
    }
}

static void
_test_thread_function(thread_context& context)
{
    LOG_VERBOSE(
        "**** {}[{}] thread started. ****",
        (context.role == thread_role_type::CREATOR    ? "CREATOR"
         : context.role == thread_role_type::ATTACHER ? "ATTACHER"
                                                      : "DESTROYER"),
        context.thread_index);

    using sc = std::chrono::system_clock;
    auto timenow = sc::now();
    std::time_t timenow_seconds = std::chrono::system_clock::to_time_t(timenow);
    auto endtime = sc::now() + std::chrono::minutes(context.duration_minutes);
    std::time_t endtime_seconds = std::chrono::system_clock::to_time_t(endtime);
    while (timenow_seconds < endtime_seconds) {

        if (context.role == thread_role_type::CREATOR) {
            _do_creator_work(context, endtime_seconds);
        } else if (context.role == thread_role_type::ATTACHER) {
            _do_attacher_work(context, endtime_seconds);
        } else if (context.role == thread_role_type::DESTROYER) {
            _do_destroyer_work(context, endtime_seconds);
        } else {
            LOG_ERROR("FATAL ERROR: Unknown thread role: {}", (uint32_t)context.role);
            context.succeeded = false;
            exit(-1);
        }

        timenow = sc::now();
        timenow_seconds = std::chrono::system_clock::to_time_t(timenow);
    }

    LOG_VERBOSE(
        "**** {}[{}] thread done. Exiting. ****",
        (context.role == thread_role_type::CREATOR    ? "CREATOR"
         : context.role == thread_role_type::ATTACHER ? "ATTACHER"
                                                      : "DESTROYER"),
        context.thread_index);
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
    // Wait for all test threads
    LOG_VERBOSE("waiting on {} test threads...", thread_table.size());
    for (auto& t : thread_table) {
        t.join();
    }

    // Wait for all extension restart threads
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

static void
_mt_prog_load_stress_test(ebpf_execution_type_t program_type, const test_control_info& test_control_info)
{
    constexpr uint32_t OBJECT_TABLE_SIZE{64};
    std::vector<object_table_entry> object_table(OBJECT_TABLE_SIZE);
    for (uint32_t index = 0; auto& entry : object_table) {
        entry.available = true;
        entry.lock = std::make_unique<std::mutex>();
        entry.object.reset();
        entry.attach = !(index % 2) ? true : false;
        entry.index = index++;
        entry.reuse_count = 0;
        entry.tag = 0xC001DEA1;
    }

    // We have 3 types of threads, so we need (test_control_info.threads_count * 3) total threads.
    size_t total_threads = ((size_t)test_control_info.threads_count * 3);
    std::vector<thread_context> thread_context_table(
        total_threads, {{}, {}, false, {}, thread_role_type::ROLE_NOT_SET, 0, 0, 0, false, 0, 0, object_table});
    std::vector<std::thread> test_thread_table(total_threads);

    // Another table for the 'extension restart' threads (1 thread per program).
    std::vector<std::string> extension_names;
    std::vector<std::thread> extension_restart_thread_table;
    std::vector<thread_context> extension_restart_thread_context_table;

    // An incrementing 'compartment Id' to ensure that _each_ 'Attacher' thread gets a unique compartment id.
    uint32_t compartment_id{1};

    for (const auto& program_info : _test_program_info) {
        const auto& program_name = program_info.first;
        const auto& program_attribs = program_info.second;
        for (size_t i = 0; i < total_threads; i++) {

            // First, prepare the context for this thread.
            auto& context_entry = thread_context_table[i];
            context_entry.program_name = program_name;

            if (!(compartment_id % 3)) {
                context_entry.role = thread_role_type::DESTROYER;
            } else if (!(compartment_id % 2)) {
                context_entry.role = thread_role_type::ATTACHER;
            } else {
                context_entry.role = thread_role_type::CREATOR;
            }

            if (program_type == EBPF_EXECUTION_NATIVE) {
                context_entry.is_native_program = true;
                if (test_control_info.use_unique_native_programs && context_entry.role == thread_role_type::CREATOR) {

                    // Create unique native programs for 'creator' threads only.
                    context_entry.file_name = _make_unique_file_copy(program_attribs.native_file_name);
                } else {

                    // Use the same file name for all 'creator' threads
                    context_entry.file_name = program_attribs.native_file_name;
                }
            } else {
                context_entry.is_native_program = false;
                context_entry.file_name = program_attribs.jit_file_name;
            }
            context_entry.thread_index = (compartment_id - 1);
            context_entry.compartment_id = compartment_id;
            context_entry.duration_minutes = test_control_info.duration_minutes;
            context_entry.extension_restart_enabled = test_control_info.extension_restart_enabled;
            compartment_id++;

            // Now create the thread.
            auto& thread_entry = test_thread_table[i];
            thread_entry = std::move(std::thread(_test_thread_function, std::ref(context_entry)));
        }

        // If requested, start the 'extension stop-and-restart' thread for extension for this program type.
        extension_names.push_back(program_attribs.extension_name);
    }

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
}

enum class program_map_usage : uint32_t
{
    IGNORE_MAP,
    USE_MAP
};

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
_prep_program(thread_context& context, program_map_usage map_usage)
{
    enum bpf_attach_type attach_type =
        context.role == thread_role_type::MONITOR_IPV4 ? BPF_CGROUP_INET4_CONNECT : BPF_CGROUP_INET6_CONNECT;
    auto [program_object, program_fd] = _load_attach_program(context, attach_type);
    if (context.succeeded == false) {
        LOG_ERROR("{}({}) - FATAL ERROR: _load_attach_program() failed.", __func__, context.thread_index);
        exit(-1);
    }

    // Stash the object pointer as we'll need it at 'close' time.
    auto& entry = context.object_table[context.thread_index];
    entry.object = std::move(program_object);
    context.program_fd = program_fd;

    if (map_usage == program_map_usage::USE_MAP) {
        // Get the map fd for the map for this program.
        context.map_fd = bpf_object__find_map_fd_by_name(entry.object.get(), context.map_name.c_str());
        if (context.map_fd < 0) {
            LOG_ERROR(
                "{}({}) FATAL ERROR: bpf_object__find_map_fd_by_name({}) failed. file_name:{}, errno:{}",
                __func__,
                context.thread_index,
                context.map_name.c_str(),
                context.file_name.c_str(),
                errno);
            context.succeeded = false;
            exit(-1);
        }
        LOG_VERBOSE(
            "{}({}) Opened fd:{} for map:{}, file_name:{}",
            __func__,
            context.thread_index,
            context.map_fd,
            context.map_name.c_str(),
            context.file_name.c_str());
    }
}

void
_invoke_test_thread_function(thread_context& context)
{
    _prep_program(context, program_map_usage::USE_MAP);
    if (context.succeeded == false) {
        LOG_ERROR("{}({}) - FATAL ERROR: _prep_program() failed.", __func__, context.thread_index);
        exit(-1);
    }
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

    // Set the timeout for connect attempts
    timeval timeout;
    timeout.tv_sec = 5; // 5 seconds
    timeout.tv_usec = 0;
    if (setsockopt(socket_handle, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) < 0) {
        LOG_ERROR("{}({}) - ERROR: setsockopt() failed. errno:{}", __func__, context.thread_index, WSAGetLastError());
        context.succeeded = false;
        exit(-1);
    }
    if (setsockopt(socket_handle, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout)) < 0) {
        LOG_ERROR("{}({}) - ERROR: setsockopt() failed. errno:{}", __func__, context.thread_index, WSAGetLastError());
        context.succeeded = false;
        exit(-1);
    }

    INETADDR_SETLOOPBACK(reinterpret_cast<PSOCKADDR>(&remote_endpoint));
    constexpr uint16_t remote_port = SOCKET_TEST_PORT;
    (reinterpret_cast<PSOCKADDR_IN>(&remote_endpoint))->sin_port = htons(remote_port);

    // Now send out a burst of TCP 'connect' attempts for the duration of the test.  The burst should keep invoking the
    // program at a very high rate while we're also restarting the extension underneath it.
    //
    // The test is considered 'failed' if the count is detected as 'stalled' (i.e. it is not continuously incrementing).
    // This is a fatal error as ebpf programs are/should be completely oblivious to such events and their invocation
    // will/should resume once the extension is reloaded. Note that the count will not exactly match the actual connect
    // attempts as the program will not be invoked for connect attempts made while the extension is restarting.
    using sc = std::chrono::steady_clock;
    auto endtime = sc::now() + std::chrono::minutes(context.duration_minutes);
    bool first_map_lookup = true;
    while (sc::now() < endtime) {

        uint16_t key = remote_port;
        uint64_t start_count = 0;
        // Map lookup before the program invocation may fail if the program has not inserted the map entry yet.
        auto result = bpf_map_lookup_elem(context.map_fd, &key, &start_count);
        if (first_map_lookup) {
            first_map_lookup = false;
        } else if (result != 0) {
            LOG_ERROR(
                "{}({}) - FATAL ERROR: bpf_map_lookup_elem() failed for fd {} before connect. errno:{}",
                __func__,
                context.thread_index,
                context.map_fd,
                errno);
            context.succeeded = false;
            exit(-1);
        }

        constexpr uint32_t BURST_SIZE = 8192;
        for (uint32_t i = 0; i < BURST_SIZE; i++) {

            // Our ebpf program _will_ fail all connect attempts to the target port, so ignore the return value.
            (void)connect(
                socket_handle,
                reinterpret_cast<SOCKADDR*>(&remote_endpoint),
                static_cast<int>(sizeof(remote_endpoint)));

            if (sc::now() >= endtime) {
                break;
            }
        }

        uint64_t end_count = 0;
        result = bpf_map_lookup_elem(context.map_fd, &key, &end_count);
        if (result != 0) {
            LOG_ERROR(
                "{}({}) - FATAL ERROR: bpf_map_lookup_elem() failed for fd {} after connect. errno:{}",
                __func__,
                context.thread_index,
                context.map_fd,
                errno);
            context.succeeded = false;
            exit(-1);
        }
        LOG_VERBOSE(
            "{}({}) connect start_count:{}, end_count:{}", __func__, context.thread_index, start_count, end_count);
        if (end_count <= start_count) {
            LOG_ERROR(
                "{}({}) - FATAL ERROR: connect count mismatched. start_count:{}, end_count:{}",
                __func__,
                context.thread_index,
                start_count,
                end_count);
            context.succeeded = false;
            exit(-1);
        }
        start_count = end_count;
    }
}

void
_mt_invoke_prog_stress_test(ebpf_execution_type_t program_type, const test_control_info& test_control_info)
{
    WSAData data{};
    auto error = WSAStartup(MAKEWORD(2, 2), &data);
    REQUIRE(error == 0);

    // As of now, we support a maximum of 2 ebpf test programs for this test.
    constexpr uint32_t MAX_TCP_CONNECT_PROGRAMS = 2;

    // Storage for object pointers for each ebpf program file opened by bpf_object__open().
    std::vector<object_table_entry> object_table(MAX_TCP_CONNECT_PROGRAMS);
    for (auto& entry : object_table) {
        entry.object.reset();
    }

    size_t total_threads = MAX_TCP_CONNECT_PROGRAMS;
    std::vector<thread_context> thread_context_table(
        total_threads, {{}, {}, false, {}, thread_role_type::ROLE_NOT_SET, 0, 0, 0, false, 0, 0, object_table});
    std::vector<std::thread> test_thread_table(total_threads);

    // Choose file extension based on execution type.
    std::string file_extension = (program_type == EBPF_EXECUTION_NATIVE) ? ".sys" : ".o";
    bool is_native = (program_type == EBPF_EXECUTION_NATIVE);

    std::vector<std::pair<std::string, std::string>> program_file_map_names = {
        {{is_native ? _make_unique_file_copy("cgroup_count_connect4.sys") : "cgroup_count_connect4.o"}, {"connect4_count_map"}},
        {{is_native ? _make_unique_file_copy("cgroup_count_connect6.sys") : "cgroup_count_connect6.o"}, {"connect6_count_map"}}};
    ASSERT(program_file_map_names.size() == MAX_TCP_CONNECT_PROGRAMS);

    for (uint32_t i = 0; i < total_threads; i++) {
        // First, prepare the context for this thread.
        auto& context_entry = thread_context_table[i];
        auto& [file_name, map_name] = program_file_map_names[i];
        context_entry.file_name = file_name;
        context_entry.is_native_program = is_native;
        context_entry.map_name = map_name;
        context_entry.role = (i == 0 ? thread_role_type::MONITOR_IPV4 : thread_role_type::MONITOR_IPV6);
        context_entry.thread_index = i;
        context_entry.compartment_id = UNSPECIFIED_COMPARTMENT_ID;
        context_entry.duration_minutes = test_control_info.duration_minutes;
        context_entry.extension_restart_enabled = test_control_info.extension_restart_enabled;

        // Now create the thread.
        auto& thread_entry = test_thread_table[i];
        thread_entry = std::move(std::thread(_invoke_test_thread_function, std::ref(context_entry)));
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
    LOG_INFO("test threads per program    : {}", test_control_info.threads_count);
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
_mt_bindmonitor_tail_call_invoke_program_test(ebpf_execution_type_t program_type, const test_control_info& test_control_info)
{
    WSAData data{};
    auto error = WSAStartup(MAKEWORD(2, 2), &data);
    REQUIRE(error == 0);

    // Choose file extension based on execution type.
    bool is_native = (program_type == EBPF_EXECUTION_NATIVE);
    std::string file_name = is_native ? _make_unique_file_copy("bindmonitor_mt_tailcall.sys") : "bindmonitor_mt_tailcall.o";

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

TEST_CASE("jit_load_attach_detach_unload_random_v4_test", "[jit_mt_stress_test]")
{
    // This test attempts to load the same JIT'ed ebpf program multiple times in different threads.  This test
    // supports two modes:
    //
    // 1. just load, attach, detach and unload the JIT'ed programs with each event happening in a different thread
    //    with all threads executing in parallel with the bare minimum synchronization between them.
    //
    // 2. Same as #1 above, but with the addition of a dedicated thread continuously unloading/reloading the provider
    //    extension (activated via a command-line argument).

    _km_test_init();
    LOG_INFO("\nStarting test *** jit_load_attach_detach_unload_random_v4_test ***");
    test_control_info local_test_control_info = _global_test_control_info;

    _print_test_control_info(local_test_control_info);
    _mt_prog_load_stress_test(EBPF_EXECUTION_JIT, local_test_control_info);
}

TEST_CASE("native_load_attach_detach_unload_random_v4_test", "[native_mt_stress_test]")
{
    // This test attempts to load the same native ebpf program multiple times in different threads. Specifically:
    //
    // - Load, attach, detach and unload the native ebpf program with each event happening in a different thread with
    //   all threads executing in parallel with the bare minimum synchronization between them.
    //
    // - Addition of a dedicated thread continuously unloading/reloading the provider extension
    //   (if specified on the command line).

    _km_test_init();
    LOG_INFO("\nStarting test *** native_load_attach_detach_unload_random_v4_test ***");
    test_control_info local_test_control_info = _global_test_control_info;

    _print_test_control_info(local_test_control_info);
    _mt_prog_load_stress_test(EBPF_EXECUTION_NATIVE, local_test_control_info);
}

TEST_CASE("native_unique_load_attach_detach_unload_random_v4_test", "[native_mt_stress_test]")
{
    // This test attempts to load a unique native ebpf program multiple times in different threads. Specifically:
    //
    // - Load, attach, detach and unload each native ebpf program with each event happening in a different thread with
    //   all threads executing in parallel with the bare minimum synchronization between them.
    //
    // - Addition of a dedicated thread continuously unloading/reloading the provider extension
    //   (if specified on the command line).

    _km_test_init();
    LOG_INFO("\nStarting test *** native_unique_load_attach_detach_unload_random_v4_test ***");
    test_control_info local_test_control_info = _global_test_control_info;

    // Use a unique native driver for each 'creator' thread.
    local_test_control_info.use_unique_native_programs = true;

    _print_test_control_info(local_test_control_info);
    _mt_prog_load_stress_test(EBPF_EXECUTION_NATIVE, local_test_control_info);
}

TEST_CASE("native_invoke_v4_v6_programs_restart_extension_test", "[native_mt_stress_test]")
{
    // Test layout:
    // 1. Create 2 'monitor' threads:
    //    - Thread #1 loads a native ebpf SOCK_ADDR program that attaches to CGROUP/CONNECT4.
    //      > This program monitors an IPv4 endpoint, 127.0.0.1:<target_port>. On every invocation, the program updates
    //        the count (TCP) 'connect' attempts in the 'connect4_count_map' map at its port.
    //    - Thread #2 loads another native ebpf SOCK_ADDR program that attaches to CGROUP/CONNECT6.
    //      > The behavior of this program is identical to that of the v4 program (loaded by thread #1), except it is
    //        invoked for IPv6 connection attempts ([::1]:<target_port>).
    //
    // 2  Until the end of test, each test thread will:
    //    - Read the initial 'connect' count from its respective 'connect<v4|v6>_map' map.
    //    - Attempt to (TCP) connect to its respective end-point 'n' times.  Make 'n' large enough (4096?) to try
    //      and collide with the extension restart event.
    //    - Read the 'connect' count its respective map after this 'burst' connect attempt.
    //    - Ensure that the counter keeps incrementing, irrespective of the netebpfext extension being restarted any
    //      number of times.  A stalled counter is a fatal bug and the test should return failure.
    //
    // 3. In parallel, start the 'extension restart' thread to continuously restart the netebpf extension
    //    (if specified on the command line).
    //
    // NOTE: The '-tt', '-er' and the '-erd' command line parameters are not used by this test.

    _km_test_init();
    LOG_INFO("\nStarting test *** native_invoke_v4_v6_programs_restart_extension_test ***");
    test_control_info local_test_control_info = _global_test_control_info;

    // This test needs only 2 threads (one per program).
    local_test_control_info.threads_count = 2;

    _print_test_control_info(local_test_control_info);
    _mt_invoke_prog_stress_test(EBPF_EXECUTION_NATIVE, local_test_control_info);
}

TEST_CASE("sockaddr_invoke_program_test", "[native_mt_stress_test]")
{
    // Test layout:
    // 1. Load the "cgroup_mt_connect6.sys" native ebpf program.
    //    - This program monitors an IPv6 endpoint, [::1]:<target_port>. On every invocation, the program returns a
    //      specific value per the following (arbitrary) algorithm:
    //      > (target_port % 3 == 0) : BPF_SOCK_ADDR_VERDICT_REJECT
    //        (target_port % 2 == 0) : BPF_SOCK_ADDR_VERDICT_PROCEED
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

    _print_test_control_info(local_test_control_info);
    _mt_bindmonitor_tail_call_invoke_program_test(EBPF_EXECUTION_NATIVE, local_test_control_info);
}

TEST_CASE("jit_unique_load_attach_detach_unload_random_v4_test", "[jit_mt_stress_test]")
{
    // This test attempts to load a unique JIT ebpf program multiple times in different threads. Specifically:
    //
    // - Load, attach, detach and unload each JIT ebpf program with each event happening in a different thread with
    //   all threads executing in parallel with the bare minimum synchronization between them.
    //
    // - Addition of a dedicated thread continuously unloading/reloading the provider extension
    //   (if specified on the command line).

    _km_test_init();
    LOG_INFO("\nStarting test *** jit_unique_load_attach_detach_unload_random_v4_test ***");
    test_control_info local_test_control_info = _global_test_control_info;

    // Use a unique JIT program for each 'creator' thread.
    local_test_control_info.use_unique_native_programs = true;

    _print_test_control_info(local_test_control_info);
    _mt_prog_load_stress_test(EBPF_EXECUTION_JIT, local_test_control_info);
}

TEST_CASE("jit_invoke_v4_v6_programs_restart_extension_test", "[jit_mt_stress_test]")
{
    // Test layout:
    // 1. Create 2 'monitor' threads:
    //    - Thread #1 loads a JIT ebpf SOCK_ADDR program that attaches to CGROUP/CONNECT4.
    //      > This program monitors an IPv4 endpoint, 127.0.0.1:<target_port>. On every invocation, the program updates
    //        the count (TCP) 'connect' attempts in the 'connect4_count_map' map at its port.
    //    - Thread #2 loads another JIT ebpf SOCK_ADDR program that attaches to CGROUP/CONNECT6.
    //      > The behavior of this program is identical to that of the v4 program (loaded by thread #1), except it is
    //        invoked for IPv6 connection attempts ([::1]:<target_port>).
    //
    // 2  Until the end of test, each test thread will:
    //    - Read the initial 'connect' count from its respective 'connect<v4|v6>_map' map.
    //    - Attempt to (TCP) connect to its respective endpoint 'n' times.  Make 'n' large enough (4096?) to try
    //      and collide with the extension restart event.
    //    - Read the 'connect' count its respective map after this 'burst' connect attempt.
    //    - Ensure that the counter keeps incrementing, irrespective of the netebpfext extension being restarted any
    //      number of times.  A stalled counter is a fatal bug and the test should return failure.
    //
    // 3. In parallel, start the 'extension restart' thread to continuously restart the netebpf extension
    //    (if specified on the command line).
    //
    // NOTE: The '-tt', '-er' and the '-erd' command line parameters are not used by this test.

    _km_test_init();
    LOG_INFO("\nStarting test *** jit_invoke_v4_v6_programs_restart_extension_test ***");
    test_control_info local_test_control_info = _global_test_control_info;

    // This test needs only 2 threads (one per program).
    local_test_control_info.threads_count = 2;

    _print_test_control_info(local_test_control_info);
    _mt_invoke_prog_stress_test(EBPF_EXECUTION_JIT, local_test_control_info);
}

TEST_CASE("jit_sockaddr_invoke_program_test", "[jit_mt_stress_test]")
{
    // Test layout:
    // 1. Load the "cgroup_mt_connect6.o" JIT ebpf program.
    //    - This program monitors an IPv6 endpoint, [::1]:<target_port>. On every invocation, the program returns a
    //      specific value per the following (arbitrary) algorithm:
    //        (target_port % 3 == 0) : BPF_SOCK_ADDR_VERDICT_REJECT
    //        (target_port % 2 == 0) : BPF_SOCK_ADDR_VERDICT_PROCEED
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
    LOG_INFO("\nStarting test *** jit_sockaddr_invoke_program_test ***");
    test_control_info local_test_control_info = _global_test_control_info;

    _print_test_control_info(local_test_control_info);
    _mt_sockaddr_invoke_program_test(EBPF_EXECUTION_JIT, local_test_control_info);
}

TEST_CASE("jit_bindmonitor_tail_call_invoke_program_test", "[jit_mt_stress_test]")
{
    // Test layout:
    // 1. Load the "bindmonitor_mt_tailcall.o" JIT ebpf program.
    // 2. Load MAX_TAIL_CALL_CNT tail call programs.
    // 3. Create the specified number of threads.
    //   - Each thread will invoke the TCP 'bind'.
    //   - This will invoke MAX_TAIL_CALL_CNT tail call programs for permit.

    _km_test_init();
    LOG_INFO("\nStarting test *** jit_bindmonitor_tailcall_invoke_program_test ***");
    test_control_info local_test_control_info = _global_test_control_info;

    _print_test_control_info(local_test_control_info);
    _mt_bindmonitor_tail_call_invoke_program_test(EBPF_EXECUTION_JIT, local_test_control_info);
}
