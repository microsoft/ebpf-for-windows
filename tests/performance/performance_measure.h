// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

// Windows build system requires include of Windows.h before other Windows
// headers.
#include <Windows.h>

#include <thread>

#include "catch_wrapper.hpp"
#include "ebpf_epoch.h"
#include "ebpf_platform.h"

#define PERFORMANCE_MEASURE_ITERATION_COUNT 1000000

/**
 * @brief Test helper function that executes a provided method on each CPU
 * iterations times, measures elapsed time and returns average elapsed time
 * accross all CPUs.
 *
 * @tparam T The helper function to run.
 */
template <typename T> class _performance_measure
{
  public:
    /**
     * @brief Construct a new performance measure object
     *
     * @param[in] worker Function under test
     * @param[in] iterations Iteration count to run.
     */
    _performance_measure(T worker, size_t iterations = PERFORMANCE_MEASURE_ITERATION_COUNT)
        : cpu_count(ebpf_get_cpu_count()), iterations(iterations), counters(cpu_count), worker(worker)
    {
        REQUIRE(ebpf_platform_initiate() == EBPF_SUCCESS);
        platform_initiated = true;
        REQUIRE(ebpf_epoch_initiate() == EBPF_SUCCESS);
        epoch_initated = true;

        start_event = CreateEvent(nullptr, true, false, nullptr);
    }
    ~_performance_measure()
    {
        if (epoch_initated)
            ebpf_epoch_terminate();
        if (platform_initiated)
            ebpf_platform_terminate();
    };

    /**
     * @brief Perform the measurement
     *
     * @return Nano-seconds elapsed for each iteration.
     */
    double
    run_test()
    {
        int32_t ready_count = 0;
        std::vector<std::thread> threads;
        for (uint32_t i = 0; i < cpu_count; i++) {
            threads.emplace_back(std::thread([i, this, &ready_count] {
                uint32_t local_cpu_id = i;
                uintptr_t thread_mask = local_cpu_id;
                thread_mask = static_cast<uintptr_t>(1) << thread_mask;
                SetThreadAffinityMask(GetCurrentThread(), thread_mask);
                ebpf_interlocked_increment_int32(&ready_count);
                WaitForSingleObject(start_event, INFINITE);
                QueryPerformanceCounter(&this->counters[local_cpu_id].first);
                for (size_t k = 0; k < iterations; k++) {
                    worker();
                }
                QueryPerformanceCounter(&this->counters[local_cpu_id].second);
            }));
        }
        // Wait for threads to spin up.
        while ((uint32_t)ready_count != cpu_count) {
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
            total_time.QuadPart += result.second.QuadPart - result.first.QuadPart;
        }
        double average_duration = static_cast<double>(total_time.QuadPart);
        average_duration /= iterations;
        average_duration /= cpu_count;
        average_duration *= 1e9;
        average_duration /= static_cast<double>(frequency.QuadPart);
        return average_duration;
    }

  private:
    const uint32_t cpu_count;
    const size_t iterations;
    T worker;
    std::vector<std::pair<LARGE_INTEGER, LARGE_INTEGER>> counters;
    HANDLE start_event;
    bool platform_initiated = false;
    bool epoch_initated = false;
};
