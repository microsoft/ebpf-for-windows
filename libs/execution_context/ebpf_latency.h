// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_result.h"
#include "ebpf_tracelog.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

    // Latency tracking modes.
#define EBPF_LATENCY_MODE_OFF 0
#define EBPF_LATENCY_MODE_PROGRAM 1
#define EBPF_LATENCY_MODE_ALL 2

    typedef struct _ebpf_latency_state
    {
        volatile long enabled; // 0 = off, 1 = program only, 2 = program + helpers
    } ebpf_latency_state_t;

    /**
     * @brief Get the current latency tracking mode.
     * @return Current latency mode (0=off, 1=program only, 2=program+helpers).
     */
    long
    ebpf_latency_get_mode();

    /**
     * @brief Enable latency tracking.
     * @param[in] mode Tracking mode: 1 = program only, 2 = program + helpers.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_INVALID_ARGUMENT Invalid mode value.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_latency_enable(uint32_t mode);

    /**
     * @brief Disable latency tracking.
     * @retval EBPF_SUCCESS The operation was successful.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_latency_disable();

    /**
     * @brief Emit an ETW event for program invocation latency.
     * @param[in] program_id The ID of the eBPF program.
     * @param[in] start_time Start timestamp in 100-ns units.
     * @param[in] end_time End timestamp in 100-ns units.
     */
    void
    ebpf_latency_emit_program_event(uint32_t program_id, uint64_t start_time, uint64_t end_time);

    /**
     * @brief Emit an ETW event for map helper function latency.
     * @param[in] program_id The ID of the owning eBPF program (0 if unknown).
     * @param[in] helper_function_id The BPF_FUNC_xxx ID of the helper function.
     * @param[in] start_time Start timestamp in 100-ns units.
     * @param[in] end_time End timestamp in 100-ns units.
     */
    void
    ebpf_latency_emit_helper_event(
        uint32_t program_id, uint32_t helper_function_id, uint64_t start_time, uint64_t end_time);

#ifdef __cplusplus
}
#endif
