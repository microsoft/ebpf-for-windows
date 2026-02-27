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

    // Maximum number of program IDs in the filter list.
#define EBPF_LATENCY_MAX_PROGRAM_FILTER 64

    typedef struct _ebpf_latency_state
    {
        volatile long enabled;        // 0 = off, 1 = program only, 2 = program + helpers
        volatile long session_active; // 0 = no active session, 1 = session in progress

        // Program ID filter list. When program_id_count == 0, all programs are tracked.
        // When program_id_count > 0, only the listed programs are tracked.
        uint32_t program_id_count;
        uint32_t program_ids[EBPF_LATENCY_MAX_PROGRAM_FILTER];
    } ebpf_latency_state_t;

    /**
     * @brief Get the current latency tracking mode.
     * @return Current latency mode (0=off, 1=program only, 2=program+helpers).
     */
    long
    ebpf_latency_get_mode();

    /**
     * @brief Check whether a given program ID should be tracked.
     * @param[in] program_id The ID of the eBPF program to check.
     * @retval TRUE if the program should be tracked (either no filter is set, or the ID is in the filter list).
     * @retval FALSE if a filter is set and the program ID is not in the list.
     */
    BOOLEAN
    ebpf_latency_should_track_program(uint32_t program_id);

    /**
     * @brief Enable latency tracking.
     * @param[in] mode Tracking mode: 1 = program only, 2 = program + helpers.
     * @param[in] program_id_count Number of program IDs in the filter list (0 = track all).
     * @param[in] program_ids Optional array of program IDs to track (NULL when program_id_count == 0).
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_INVALID_ARGUMENT Invalid mode value or program_id_count exceeds maximum.
     * @retval EBPF_INVALID_STATE Another latency tracking session is already active.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_latency_enable(
        uint32_t mode, uint32_t program_id_count, _In_reads_opt_(program_id_count) const uint32_t* program_ids);

    /**
     * @brief Disable latency tracking and release the session.
     * @retval EBPF_SUCCESS The operation was successful.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_latency_disable();

    /**
     * @brief Emit an ETW event for program invocation latency.
     * @param[in] program_id The ID of the eBPF program.
     * @param[in] program_name The name of the eBPF program (may be NULL).
     * @param[in] start_time Start timestamp in 100-ns units.
     * @param[in] end_time End timestamp in 100-ns units.
     */
    void
    ebpf_latency_emit_program_event(
        uint32_t program_id, _In_opt_ const cxplat_utf8_string_t* program_name, uint64_t start_time, uint64_t end_time);

    /**
     * @brief Emit an ETW event for map helper function latency.
     * @param[in] program_id The ID of the owning eBPF program (0 if unknown).
     * @param[in] helper_function_id The BPF_FUNC_xxx ID of the helper function.
     * @param[in] map_name The name of the map being operated on (may be NULL).
     * @param[in] start_time Start timestamp in 100-ns units.
     * @param[in] end_time End timestamp in 100-ns units.
     */
    void
    ebpf_latency_emit_helper_event(
        uint32_t program_id,
        uint32_t helper_function_id,
        _In_opt_ const cxplat_utf8_string_t* map_name,
        uint64_t start_time,
        uint64_t end_time);

#ifdef __cplusplus
}
#endif
