// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "ebpf_mt_stress.h"

static void
_start_invoke_workers(
    _Inout_ std::vector<std::thread>& invoke_threads,
    uint32_t invoke_thread_count,
    _Inout_ std::atomic<bool>& stop_all,
    _Inout_ std::atomic<bool>& stop_invoke_workers,
    _Inout_ std::atomic<uint64_t>& invoke_count,
    const std::function<void()>& invoke_routine)
{
    stop_invoke_workers.store(false);
    invoke_threads.clear();
    invoke_threads.reserve(invoke_thread_count);
    for (uint32_t i = 0; i < invoke_thread_count; i++) {
        invoke_threads.emplace_back([&]() {
            while (!stop_all.load() && !stop_invoke_workers.load()) {
                invoke_routine();
                ++invoke_count;
            }
        });
    }
}

static void
_stop_and_join_invoke_workers(
    _Inout_ std::vector<std::thread>& invoke_threads, _Inout_ std::atomic<bool>& stop_invoke_workers)
{
    // Ensure no invoke operation is in flight when extension restart begins.
    stop_invoke_workers.store(true);
    for (auto& thread : invoke_threads) {
        thread.join();
    }
    invoke_threads.clear();
}

static bool
_run_extension_restart_epochs(
    bool extension_restart_enabled,
    uint32_t extension_restart_delay_ms,
    const std::function<bool()>& extension_restart_routine,
    _In_ const std::chrono::steady_clock::time_point& end_time,
    _Inout_ std::vector<std::thread>& invoke_threads,
    uint32_t invoke_thread_count,
    _Inout_ std::atomic<bool>& stop_all,
    _Inout_ std::atomic<bool>& stop_invoke_workers,
    _Inout_ std::atomic<bool>& extension_restarting,
    _Inout_ std::atomic<uint64_t>& invoke_count,
    const std::function<void()>& invoke_routine)
{
    using steady_clock = std::chrono::steady_clock;
    if (!extension_restart_enabled || !extension_restart_routine) {
        std::this_thread::sleep_until(end_time);
        return true;
    }

    auto restart_delay = std::chrono::milliseconds(extension_restart_delay_ms);
    auto next_restart_time = steady_clock::now() + restart_delay;
    while (steady_clock::now() < end_time) {
        auto wake_time = (next_restart_time < end_time) ? next_restart_time : end_time;
        std::this_thread::sleep_until(wake_time);
        if (steady_clock::now() >= end_time) {
            break;
        }

        // Before restarting the extension, stop invocation completely and wait for threads to exit.
        _stop_and_join_invoke_workers(invoke_threads, stop_invoke_workers);
        extension_restarting.store(true);
        if (!extension_restart_routine()) {
            extension_restarting.store(false);
            stop_all.store(true);
            return false;
        }
        extension_restarting.store(false);
        if (stop_all.load()) {
            break;
        }

        // Resume invocation with a fresh set of invoke worker threads after successful restart.
        _start_invoke_workers(
            invoke_threads, invoke_thread_count, stop_all, stop_invoke_workers, invoke_count, invoke_routine);
        next_restart_time = steady_clock::now() + restart_delay;
    }

    return true;
}

// Runs the common attach/invoke/detach race pattern for stress tests.
// Parameters:
// - invoke_routine: Worker operation that continuously invokes the program.
// - detach_routine: Churn operation that detaches active attachments. Receives `extension_restarting` state.
// - attach_routine: Churn operation that reattaches active attachments. Receives `extension_restarting` state.
// - duration_minutes: Total test run duration.
// - invoke_thread_count: Number of invoke worker threads.
// - attach_detach_delay_ms: Delay between churn loop iterations.
// - extension_restart_enabled: Enables periodic extension restart orchestration.
// - extension_restart_delay_ms: Restart period in milliseconds when restart is enabled.
// - extension_restart_routine: UM/KM-specific restart callback; returns false on restart failure.
// Returns:
// - true if the race completed without restart failure; false if a restart callback failed.
bool
run_attach_invoke_detach_race(
    const std::function<void()>& invoke_routine,
    const std::function<void(bool extension_restarting)>& detach_routine,
    const std::function<void(bool extension_restarting)>& attach_routine,
    uint32_t duration_minutes,
    uint32_t invoke_thread_count,
    uint32_t attach_detach_delay_ms,
    bool extension_restart_enabled,
    uint32_t extension_restart_delay_ms,
    const std::function<bool()>& extension_restart_routine)
{
    if (invoke_thread_count == 0) {
        invoke_thread_count = 1;
    }
    if (attach_detach_delay_ms == 0) {
        attach_detach_delay_ms = 10;
    }

    std::atomic<bool> stop_all{false};
    // This flag controls a full stop/recreate cycle for invoke workers at each restart epoch.
    std::atomic<bool> stop_invoke_workers{false};
    // True only while the extension restart callback is actively running.
    // Churn lambdas use this to suppress expected attach/detach failures during restart.
    std::atomic<bool> extension_restarting{false};
    std::atomic<uint64_t> invoke_count{0};
    std::atomic<uint64_t> attach_detach_count{0};
    std::atomic<uint64_t> extension_restart_count{0};
    std::atomic<uint64_t> extension_restart_failure_count{0};

    std::vector<std::thread> invoke_threads{};
    _start_invoke_workers(
        invoke_threads, invoke_thread_count, stop_all, stop_invoke_workers, invoke_count, invoke_routine);

    std::thread detach_attach_thread([&]() {
        // This thread deliberately keeps running during extension restart windows.
        // The churn path is intentionally rude and independent of restart orchestration.
        while (!stop_all.load()) {
            bool restart_in_progress = extension_restarting.load();
            detach_routine(restart_in_progress);
            attach_routine(restart_in_progress);
            ++attach_detach_count;
            std::this_thread::sleep_for(std::chrono::milliseconds(attach_detach_delay_ms));
        }
    });

    using steady_clock = std::chrono::steady_clock;
    auto test_start_time = steady_clock::now();
    auto end_time = steady_clock::now() + std::chrono::minutes(duration_minutes);
    auto extension_restart_and_count = [&]() -> bool {
        bool restart_ok = extension_restart_routine();
        if (restart_ok) {
            ++extension_restart_count;
        } else {
            ++extension_restart_failure_count;
            LOG_ERROR("Extension restart failed during stress test restart epoch.");
        }
        return restart_ok;
    };
    bool restart_succeeded = _run_extension_restart_epochs(
        extension_restart_enabled,
        extension_restart_delay_ms,
        extension_restart_and_count,
        end_time,
        invoke_threads,
        invoke_thread_count,
        stop_all,
        stop_invoke_workers,
        extension_restarting,
        invoke_count,
        invoke_routine);

    // Test has completed; stop all worker threads and perform final cleanup joins.
    stop_all.store(true);
    _stop_and_join_invoke_workers(invoke_threads, stop_invoke_workers);
    detach_attach_thread.join();
    auto elapsed_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(steady_clock::now() - test_start_time).count();

    LOG_INFO(
        "Race run complete: invoke_threads={}, attach_delay_ms={}, invokes={}, detach+attach={}, "
        "ext_restart={}, ext_restart_period_ms={}, ext_restarts={}, ext_restart_failures={}, elapsed_ms={}",
        invoke_thread_count,
        attach_detach_delay_ms,
        invoke_count.load(),
        attach_detach_count.load(),
        extension_restart_enabled ? "enabled" : "disabled",
        extension_restart_enabled ? std::to_string(extension_restart_delay_ms) : "n/a",
        extension_restart_count.load(),
        extension_restart_failure_count.load(),
        elapsed_ms);
    return restart_succeeded;
}
