// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#include "ebpf_platform.h"

#include <stdexcept>
#include <thread>
#include <vector>

#define PERFORMANCE_MEASURE_ITERATION_COUNT 1000000
#define PERFORMANCE_MEASURE_TIMEOUT 60000
#define PERFORMANCE_MEASURE_BATCH_SIZE 1024

/**
 * @brief Test helper function that executes a provided method on each CPU
 * iterations times, measures elapsed time and returns average elapsed time
 * across all CPUs.
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
        : cpu_count(ebpf_get_cpu_count()), iterations(iterations), counters(cpu_count), worker(worker),
          preemptible(preemptible), test_name(test_name)
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
        int32_t ready_count = 0;
        std::vector<std::thread> threads;
        for (uint32_t i = 0; i < cpu_count; i++) {
            threads.emplace_back(std::thread([i, this, &ready_count] {
                uint32_t local_cpu_id = i;
                usersim_set_affinity_and_priority_override(local_cpu_id);
                uintptr_t thread_mask = local_cpu_id;
                thread_mask = static_cast<uintptr_t>(1) << thread_mask;
                SetThreadAffinityMask(GetCurrentThread(), thread_mask);
                ebpf_interlocked_increment_int32(&ready_count);
                WaitForSingleObject(start_event, INFINITE);
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
                        counters[local_cpu_id].QuadPart += end_time.QuadPart - start_time.QuadPart;
                        if (!preemptible) {
                            KeLowerIrql(old_irql);
                        }
                        usersim_clear_affinity_and_priority_override();
                        usersim_set_affinity_and_priority_override(local_cpu_id);
                        if (!preemptible) {
                            old_irql = KeRaiseIrqlToDpcLevel();
                        }
                        QueryPerformanceCounter(&start_time);
                    }
                    if constexpr (std::is_same<T, void(__cdecl*)(uint32_t)>::value) {
                        worker(local_cpu_id);
                    } else {
                        worker();
                    }
                }
                QueryPerformanceCounter(&end_time);
                counters[local_cpu_id].QuadPart += end_time.QuadPart - start_time.QuadPart;
                if (!preemptible) {
                    KeLowerIrql(old_irql);
                }
                usersim_clear_affinity_and_priority_override();
            }));
        }
        // Wait for threads to spin up.
        auto tick_count = GetTickCount64();
        while ((uint32_t)ready_count != cpu_count) {
            if ((GetTickCount64() - tick_count) > PERFORMANCE_MEASURE_TIMEOUT) {
                throw new std::runtime_error("Test timed out waiting for worker to start");
            }
            Sleep(1);
        }
        SetEvent(start_event);
        for (auto& thread : threads) {
            thread.join();
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
    const uint32_t cpu_count;
    const size_t iterations;
    T worker;
    std::vector<LARGE_INTEGER> counters;
    HANDLE start_event;
    bool preemptible;
    const char* test_name;
};
