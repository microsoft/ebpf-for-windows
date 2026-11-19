// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

#include "ebpf_platform.h"
#include "usersim/ke.h"

#include <atomic>
#include <bit>
#include <climits>
#include <stdexcept>
#include <system_error>
#include <thread>
#include <vector>

inline DWORD_PTR
get_stress_test_cpu_affinity(DWORD_PTR process_mask)
{
    if (process_mask == 0) {
        throw std::system_error(ERROR_NOT_SUPPORTED, std::system_category(), "Empty stress-test process affinity");
    }

    // Keep CPU 0 free, unless it is the only processor available to this process.
    DWORD_PTR worker_mask = process_mask & ~DWORD_PTR{1};
    if (worker_mask == 0) {
        worker_mask = process_mask;
    }
    return worker_mask;
}

inline DWORD_PTR
get_stress_test_cpu_affinity()
{
    DWORD_PTR process_mask = 0;
    DWORD_PTR system_mask = 0;
    if (!GetProcessAffinityMask(GetCurrentProcess(), &process_mask, &system_mask)) {
        throw std::system_error(GetLastError(), std::system_category(), "GetProcessAffinityMask");
    }
    return get_stress_test_cpu_affinity(process_mask);
}

#define PERFORMANCE_MEASURE_ITERATION_COUNT 1000000
#define PERFORMANCE_MEASURE_TIMEOUT 60000
#define PERFORMANCE_MEASURE_BATCH_SIZE 1024

/**
 * @brief Test helper function that executes a provided method on each worker CPU
 * iterations times, measures elapsed time and returns average elapsed time
 * across the worker CPUs, leaving CPU 0 available for the test runner.
 *
 * @tparam T The helper function to run.
 */
template <typename T> class _performance_measure
{
  public:
    /**
     * @brief Construct a new performance measure object.
     *
     * @param[in] test_name Display name of the test to run.
     * @param[in] preemptible Run the test function in preemptible mode.
     * @param[in] worker Function under test
     * @param[in] iterations Iteration count to run.
     */
    _performance_measure(
        _In_z_ const char* test_name,
        bool preemptible,
        T worker,
        size_t iterations = PERFORMANCE_MEASURE_ITERATION_COUNT)
        : affinity_mask(get_stress_test_cpu_affinity()), cpu_count(static_cast<uint32_t>(std::popcount(affinity_mask))),
          iterations(iterations), worker(worker), counters(cpu_count), preemptible(preemptible), test_name(test_name)
    {
        start_event = CreateEvent(nullptr, true, false, nullptr);
    }
    ~_performance_measure() { CloseHandle(start_event); }

    /**
     * @brief Perform the measurement.
     *
     * @param[in] multiplier Count of tests each invocation of worker represents.
     */
    void
    run_test(size_t multiplier = 1)
    {
        std::atomic<uint32_t> ready_count{0};
        std::atomic<DWORD> affinity_error{ERROR_SUCCESS};
        std::vector<std::thread> threads;
        for (uint32_t cpu_id = 0; cpu_id < sizeof(DWORD_PTR) * CHAR_BIT; cpu_id++) {
            DWORD_PTR thread_mask = DWORD_PTR{1} << cpu_id;
            if ((affinity_mask & thread_mask) == 0) {
                continue;
            }
            uint32_t worker_id = static_cast<uint32_t>(threads.size());
            threads.emplace_back(std::thread([worker_id, thread_mask, this, &ready_count, &affinity_error] {
                GROUP_AFFINITY affinity{};
                if (!GetThreadGroupAffinity(GetCurrentThread(), &affinity)) {
                    affinity_error.store(GetLastError());
                    ++ready_count;
                    return;
                }
                affinity.Mask = thread_mask;
                // Keep usersim's cached affinity in sync so lowering IRQL cannot migrate a worker onto CPU 0.
                if (!usersim_set_current_thread_affinity(&affinity, nullptr)) {
                    affinity_error.store(GetLastError());
                    ++ready_count;
                    return;
                }
                ++ready_count;
                WaitForSingleObject(start_event, INFINITE);
                if (affinity_error.load() != ERROR_SUCCESS) {
                    return;
                }
                KIRQL old_irql = PASSIVE_LEVEL;
                if (!preemptible) {
                    old_irql = KeRaiseIrqlToDpcLevel();
                }
                LARGE_INTEGER start_time;
                LARGE_INTEGER end_time;

                QueryPerformanceCounter(&start_time);
                for (size_t k = 0; k < iterations; k++) {
                    if (k % PERFORMANCE_MEASURE_BATCH_SIZE == 0) {
                        QueryPerformanceCounter(&end_time);
                        counters[worker_id].QuadPart += end_time.QuadPart - start_time.QuadPart;
                        if (!preemptible) {
                            KeLowerIrql(old_irql);
                        }
                        if (!preemptible) {
                            old_irql = KeRaiseIrqlToDpcLevel();
                        }
                        QueryPerformanceCounter(&start_time);
                    }
                    if constexpr (std::is_same<T, void(__cdecl*)(uint32_t)>::value) {
                        // Keep logical worker IDs dense: worker 0 coordinates the rolling LRU test.
                        worker(worker_id);
                    } else {
                        worker();
                    }
                }
                QueryPerformanceCounter(&end_time);
                counters[worker_id].QuadPart += end_time.QuadPart - start_time.QuadPart;
                if (!preemptible) {
                    KeLowerIrql(old_irql);
                }
            }));
        }
        // Wait for threads to spin up.
        auto tick_count = GetTickCount64();
        while (ready_count.load() != cpu_count) {
            if ((GetTickCount64() - tick_count) > PERFORMANCE_MEASURE_TIMEOUT) {
                affinity_error.store(ERROR_TIMEOUT);
                break;
            }
            Sleep(1);
        }
        SetEvent(start_event);
        for (auto& thread : threads) {
            thread.join();
        }
        if (affinity_error.load() != ERROR_SUCCESS) {
            throw std::system_error(affinity_error.load(), std::system_category(), "Starting performance workers");
        }
        LARGE_INTEGER total_time{};
        LARGE_INTEGER frequency{};
        QueryPerformanceFrequency(&frequency);
        for (const auto& result : counters) {
            total_time.QuadPart += result.QuadPart;
        }
        double average_duration = static_cast<double>(total_time.QuadPart);
        average_duration /= iterations;
        average_duration /= cpu_count;
        average_duration *= 1e9;
        average_duration /= static_cast<double>(frequency.QuadPart);
        average_duration /= multiplier;
        printf("%s,%d,%.0f\n", test_name, preemptible, average_duration);
    }

  private:
    const DWORD_PTR affinity_mask;
    const uint32_t cpu_count;
    const size_t iterations;
    T worker;
    std::vector<LARGE_INTEGER> counters;
    HANDLE start_event;
    bool preemptible;
    const char* test_name;
};
