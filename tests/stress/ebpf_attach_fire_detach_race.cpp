// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "ebpf_mt_stress.h"

void
run_attach_invoke_detach_race(
    const std::function<void()>& invoke_routine,
    const std::function<void()>& detach_routine,
    const std::function<void()>& attach_routine,
    uint32_t duration_minutes,
    uint32_t invoke_thread_count,
    uint32_t attach_detach_delay_ms)
{
    if (invoke_thread_count == 0) {
        invoke_thread_count = 1;
    }
    if (attach_detach_delay_ms == 0) {
        attach_detach_delay_ms = 10;
    }

    std::atomic<bool> stop{false};
    std::atomic<uint64_t> invoke_count{0};
    std::atomic<uint64_t> attach_detach_count{0};

    std::vector<std::thread> invoke_threads;
    invoke_threads.reserve(invoke_thread_count);
    for (uint32_t i = 0; i < invoke_thread_count; i++) {
        invoke_threads.emplace_back([&]() {
            while (!stop.load()) {
                invoke_routine();
                ++invoke_count;
            }
        });
    }

    std::thread detach_attach_thread([&]() {
        while (!stop.load()) {
            detach_routine();
            attach_routine();
            ++attach_detach_count;
            std::this_thread::sleep_for(std::chrono::milliseconds(attach_detach_delay_ms));
        }
    });

    using steady_clock = std::chrono::steady_clock;
    auto end_time = steady_clock::now() + std::chrono::minutes(duration_minutes);
    std::this_thread::sleep_until(end_time);

    stop.store(true);
    for (auto& thread : invoke_threads) {
        thread.join();
    }
    detach_attach_thread.join();

    LOG_INFO(
        "Race run complete: invoke_threads={}, attach_delay_ms={}, invokes={}, detach+attach={}",
        invoke_thread_count,
        attach_detach_delay_ms,
        invoke_count.load(),
        attach_detach_count.load());
}
