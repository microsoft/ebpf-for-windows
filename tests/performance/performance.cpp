// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN

#include "catch_wrapper.hpp"
#include "performance_measure.h"
#include "wer_report.hpp"

TEST_CASE("stress worker affinity selection", "[performance_affinity]")
{
    REQUIRE(get_stress_test_cpu_affinity(1) == 1);
    REQUIRE(get_stress_test_cpu_affinity(0x81) == 0x80);
    REQUIRE(get_stress_test_cpu_affinity(0xa0) == 0xa0);
    REQUIRE_THROWS_AS(get_stress_test_cpu_affinity(0), std::system_error);
}

TEST_CASE("performance workers reserve CPU 0", "[performance_affinity]")
{
    DWORD_PTR original_mask = 0;
    DWORD_PTR system_mask = 0;
    REQUIRE(GetProcessAffinityMask(GetCurrentProcess(), &original_mask, &system_mask));
    REQUIRE(original_mask != 0);
    static std::atomic<DWORD_PTR> observed_cpus{0};
    static std::atomic<DWORD_PTR> observed_workers{0};
    static std::atomic<bool> affinity_preserved{true};
    observed_cpus.store(0);
    observed_workers.store(0);
    affinity_preserved.store(true);
    auto worker = +[](uint32_t worker_id) {
        DWORD_PTR expected_affinity = DWORD_PTR{1} << GetCurrentProcessorNumber();
        auto old_irql = KeRaiseIrqlToDpcLevel();
        KeLowerIrql(old_irql);
        GROUP_AFFINITY affinity{};
        if (!GetThreadGroupAffinity(GetCurrentThread(), &affinity) || affinity.Mask != expected_affinity) {
            affinity_preserved.store(false);
        }
        observed_cpus.fetch_or(DWORD_PTR{1} << GetCurrentProcessorNumber());
        observed_workers.fetch_or(DWORD_PTR{1} << worker_id);
    };
    _performance_measure measure("CPU reservation", true, worker, 1);
    measure.run_test();

    DWORD_PTR expected_mask = original_mask & ~DWORD_PTR{1};
    if (expected_mask == 0) {
        expected_mask = original_mask;
    }
    REQUIRE(observed_cpus.load() == expected_mask);
    REQUIRE(affinity_preserved.load());
    // Worker IDs must remain dense even if the allowed CPU numbers are not.
    REQUIRE(
        observed_workers.load() == (~DWORD_PTR{0} >> (sizeof(DWORD_PTR) * CHAR_BIT - std::popcount(expected_mask))));
    DWORD_PTR process_mask = 0;
    REQUIRE(GetProcessAffinityMask(GetCurrentProcess(), &process_mask, &system_mask));
    REQUIRE(process_mask == original_mask);
}
