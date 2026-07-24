// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "catch_wrapper.hpp"
#include "common_tests.h"
#include "ebpf_mt_stress.h"
#include "helpers.h"
#include "hook_helper.h"
#include "sample_ext_test_common.h"
#include "test_helper.hpp"

#include <atomic>
#include <memory>
#include <vector>

void
test_process_cleanup()
{
}

TEST_CASE("sample_attach_invoke_detach_race_um", "[stress_um]")
{
    LOG_INFO("\nStarting test *** sample_attach_invoke_detach_race_um ***");

    _test_helper_end_to_end test_helper;
    test_helper.initialize();

    hook_helper_t attach_helper(EBPF_ATTACH_TYPE_SAMPLE);
    auto hook = std::make_unique<single_instance_hook_t>(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE);
    REQUIRE(hook->initialize() == EBPF_SUCCESS);
    program_info_provider_t sample_program_info;
    REQUIRE(sample_program_info.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);

    bpf_object* object = nullptr;
    bpf_program* program = nullptr;
    fd_t program_fd = -1;
    fd_t map_fd = -1;
    REQUIRE(
        sample_stress_load_program(
            "test_sample_ebpf_um.dll", BPF_PROG_TYPE_UNSPEC, &object, &program, &program_fd, &map_fd) == 0);
    (void)map_fd;

    auto test_control = get_test_control_info();
    uint32_t duration_minutes =
        test_control.duration_minutes == 0 ? DEFAULT_DURATION_MINUTES : test_control.duration_minutes;
    uint32_t invoke_thread_count =
        test_control.threads_count == 0 ? DEFAULT_UM_INVOKE_THREAD_COUNT : test_control.threads_count;
    uint32_t attach_detach_delay_ms =
        test_control.attach_detach_delay_ms == 0 ? DEFAULT_ATTACH_DETACH_DELAY_MS : test_control.attach_detach_delay_ms;
    bool extension_restart_enabled = test_control.extension_restart_enabled;
    // For sample attach/invoke/detach race tests, the default restart period is 10x attach/detach delay.
    uint32_t extension_restart_delay_ms = test_control.extension_restart_delay_ms == 0
                                              ? (attach_detach_delay_ms * 10)
                                              : test_control.extension_restart_delay_ms;
    if (extension_restart_enabled &&
        (static_cast<uint64_t>(extension_restart_delay_ms) < static_cast<uint64_t>(attach_detach_delay_ms) * 2)) {
        LOG_ERROR(
            "Invalid extension restart delay: {} ms. For race tests with -er, -erd must be at least 2x -ad ({} ms).",
            extension_restart_delay_ms,
            attach_detach_delay_ms);
        REQUIRE(false);
    }
    std::vector<uint32_t> attach_data(invoke_thread_count);
    for (uint32_t i = 0; i < invoke_thread_count; i++) {
        attach_data[i] = i;
        REQUIRE(attach_helper.attach(program, &attach_data[i], sizeof(attach_data[i])) != nullptr);
    }

    constexpr int value_size = 32;
    std::atomic<uint32_t> next_worker_id{0};
    std::atomic<uint64_t> detach_failure_count{0};
    std::atomic<uint64_t> attach_failure_count{0};
    auto invoke_routine = [&]() {
        thread_local const uint32_t worker_id = next_worker_id.fetch_add(1);
        uint32_t attach_value = attach_data[worker_id % invoke_thread_count];
        uint8_t context_data[value_size] = {};
        memcpy(context_data, "rainy", 5);
        sample_program_context_header_t header{};
        sample_program_context_t* context = &header.context;
        context->data_start = context_data;
        context->data_end = context_data + value_size;
        uint32_t hook_result = 0;
        (void)hook->fire(&attach_value, sizeof(attach_value), context, &hook_result);
    };
    auto detach_routine = [&](bool extension_restarting) {
        for (uint32_t i = 0; i < invoke_thread_count; i++) {
            if (attach_helper.detach(program_fd, &attach_data[i], sizeof(attach_data[i])) != EBPF_SUCCESS) {
                // During restart windows, attach/detach failures are expected and should not count as test failures.
                if (!extension_restarting) {
                    ++detach_failure_count;
                }
            }
        }
    };
    auto attach_routine = [&](bool extension_restarting) {
        for (uint32_t i = 0; i < invoke_thread_count; i++) {
            if (attach_helper.attach(program, &attach_data[i], sizeof(attach_data[i])) == nullptr) {
                // During restart windows, attach/detach failures are expected and should not count as test failures.
                if (!extension_restarting) {
                    ++attach_failure_count;
                }
            }
        }
    };
    auto extension_restart_routine = [&]() -> bool {
        // Restarting the UM mock provider is modeled by recreating the single-instance hook used for invoke.
        // Attach/detach churn stays independent and continues through restart windows.
        hook.reset();
        hook = std::make_unique<single_instance_hook_t>(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE);
        return hook->initialize() == EBPF_SUCCESS;
    };

    REQUIRE(run_attach_invoke_detach_race(
        invoke_routine,
        detach_routine,
        attach_routine,
        duration_minutes,
        invoke_thread_count,
        attach_detach_delay_ms,
        extension_restart_enabled,
        extension_restart_delay_ms,
        extension_restart_routine));
    LOG_INFO(
        "Race attach/detach failures: detach_failures={}, attach_failures={}",
        detach_failure_count.load(),
        attach_failure_count.load());

    for (uint32_t i = 0; i < invoke_thread_count; i++) {
        (void)attach_helper.detach(program_fd, &attach_data[i], sizeof(attach_data[i]));
    }
    sample_stress_close_program(object);
}
