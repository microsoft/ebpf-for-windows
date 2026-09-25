// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf/libbpf.h"
#include "catch_wrapper.hpp"
#include "ebpf_api.h"
#include "ebpf_mt_stress.h"
#include "sample_ext_helper.h"
#include "sample_ext_test_common.h"

#include <io.h>

void
test_process_cleanup()
{}

static void
_detach_all_programs()
{
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

TEST_CASE("sample_attach_invoke_detach_race_km", "[stress_km][ebpfcore]")
{
    _detach_all_programs();
    LOG_INFO("\nStarting test *** sample_attach_invoke_detach_race_km ***");

    bpf_object* object = nullptr;
    bpf_program* program = nullptr;
    fd_t program_fd = -1;
    fd_t map_fd = -1;
    REQUIRE(
        sample_stress_load_program(
            "test_sample_ebpf.sys", BPF_PROG_TYPE_SAMPLE, &object, &program, &program_fd, &map_fd) == 0);

    auto test_control = get_test_control_info();
    uint32_t duration_minutes =
        test_control.duration_minutes == 0 ? DEFAULT_DURATION_MINUTES : test_control.duration_minutes;
    uint32_t invoke_thread_count = test_control.threads_count == 0 ? default_km_invoke_thread_count() : test_control.threads_count;
    if (invoke_thread_count == 0) {
        invoke_thread_count = 1;
    }
    uint32_t attach_detach_delay_ms =
        test_control.attach_detach_delay_ms == 0 ? DEFAULT_ATTACH_DETACH_DELAY_MS : test_control.attach_detach_delay_ms;
    bool extension_restart_enabled = test_control.extension_restart_enabled;
    uint32_t extension_restart_delay_ms = test_control.extension_restart_delay_ms == 0
                                              ? attach_detach_delay_ms * 10
                                              : test_control.extension_restart_delay_ms;
    if (extension_restart_enabled && static_cast<uint64_t>(extension_restart_delay_ms) < static_cast<uint64_t>(attach_detach_delay_ms) * 2) {
        LOG_ERROR(
            "Invalid extension restart delay: {} ms. For race tests with -er, -erd must be at least 2x -ad ({} ms).",
            extension_restart_delay_ms,
            attach_detach_delay_ms);
        REQUIRE(false);
    }

    std::vector<uint32_t> attach_data(invoke_thread_count);
    std::vector<bpf_link*> links(invoke_thread_count, nullptr);
    for (uint32_t index = 0; index < invoke_thread_count; index++) {
        attach_data[index] = index;
        REQUIRE(
            ebpf_program_attach(
                program,
                &EBPF_ATTACH_TYPE_SAMPLE,
                &attach_data[index],
                sizeof(attach_data[index]),
                &links[index]) == EBPF_SUCCESS);
    }

    std::atomic<uint32_t> next_worker_id{0};
    std::atomic<uint64_t> detach_failure_count{0};
    std::atomic<uint64_t> attach_failure_count{0};
    std::atomic<uint64_t> invoke_failure_count{0};
    std::atomic<uint64_t> initialize_failure_count{0};
    auto invoke_routine = [&]() {
        thread_local const uint32_t worker_id = next_worker_id.fetch_add(1);
        thread_local _sample_extension_helper sample_extension_client(false);
        thread_local const bool initialized = sample_extension_client.initialize();
        thread_local bool initialization_failure_reported = false;
        if (!initialized) {
            if (!initialization_failure_reported) {
                ++initialize_failure_count;
                LOG_ERROR("Invoke thread {}: failed to open sample extension device handle.", worker_id);
                initialization_failure_reported = true;
            }
            return;
        }
        thread_local std::vector<char> input_buffer = {'r', 'a', 'i', 'n', 'y'};
        thread_local std::vector<char> output_buffer(256);
        uint32_t attach_value = attach_data[worker_id % invoke_thread_count];
        if (!sample_extension_client.try_invoke_by_attach_parameter(
                &attach_value, sizeof(attach_value), input_buffer, output_buffer) &&
            GetLastError() != ERROR_NOT_FOUND) {
            ++invoke_failure_count;
        }
    };
    auto detach_routine = [&](bool extension_restarting) {
        for (uint32_t index = 0; index < invoke_thread_count; index++) {
            if (links[index] != nullptr) {
                int result = bpf_link__destroy(links[index]);
                links[index] = nullptr;
                if (result != 0 && !extension_restarting) {
                    ++detach_failure_count;
                }
            }
        }
    };
    auto attach_routine = [&](bool extension_restarting) {
        for (uint32_t index = 0; index < invoke_thread_count; index++) {
            ebpf_result_t result = ebpf_program_attach(
                program,
                &EBPF_ATTACH_TYPE_SAMPLE,
                &attach_data[index],
                sizeof(attach_data[index]),
                &links[index]);
            if (result != EBPF_SUCCESS && !extension_restarting) {
                ++attach_failure_count;
            }
        }
    };
    auto extension_restart_routine = []() { return restart_extension("SampleEbpfExt", 10); };

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
        "Race attach/detach/invoke failures: detach_failures={}, attach_failures={}, invoke_failures={}, "
        "initialize_failures={}",
        detach_failure_count.load(),
        attach_failure_count.load(),
        invoke_failure_count.load(),
        initialize_failure_count.load());
    REQUIRE(initialize_failure_count.load() == 0);

    for (uint32_t index = 0; index < invoke_thread_count; index++) {
        if (links[index] != nullptr) {
            bpf_link__destroy(links[index]);
        }
    }
    sample_stress_close_program(object);
}