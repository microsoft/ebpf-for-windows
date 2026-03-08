// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_result.h"
#include "ebpf_tracelog.h"

#include <intrin.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

    // Latency tracking modes.
#define EBPF_LATENCY_MODE_OFF 0
#define EBPF_LATENCY_MODE_PROGRAM 1
#define EBPF_LATENCY_MODE_ALL 2

    // Latency tracking flags (bitmask).
#define EBPF_LATENCY_FLAG_CORRELATION_ID 0x1 // Generate per-invocation correlation IDs.

    // Maximum number of program IDs in the filter list.
#define EBPF_LATENCY_MAX_PROGRAM_FILTER 64

    // Ring buffer record count limits.
#define EBPF_LATENCY_DEFAULT_RECORDS_PER_CPU 100000 // Default: 100,000 records per CPU (~2.3 MB).
#define EBPF_LATENCY_MIN_RECORDS_PER_CPU 1000       // Minimum: 1,000 records.
#define EBPF_LATENCY_MAX_RECORDS_PER_CPU 10000000   // Maximum: 10,000,000 records (~229 MB).

    // Latency event types.
#define EBPF_LATENCY_EVENT_PROGRAM_START 0
#define EBPF_LATENCY_EVENT_PROGRAM_END 1
#define EBPF_LATENCY_EVENT_HELPER_START 2
#define EBPF_LATENCY_EVENT_HELPER_END 3

    // Compact latency event record. No strings — IDs only.
    typedef struct _ebpf_latency_record
    {
        uint64_t timestamp;          // 8 B — rdtsc value (raw cycles).
        uint32_t correlation_id;     // 4 B — per-CPU monotonic counter (0 if correlation disabled).
        uint32_t program_id;         // 4 B — ebpf_core_object_t.id.
        uint16_t helper_function_id; // 2 B — BPF_FUNC_xxx (0 = program start/end).
        uint16_t map_id;             // 2 B — ebpf_map_t.id (0 if N/A).
        uint8_t event_type;          // 1 B — EBPF_LATENCY_EVENT_*.
        uint8_t cpu_id;              // 1 B — processor number.
        uint8_t reserved[2];         // 2 B — padding to 24 bytes.
    } ebpf_latency_record_t;

    // Per-CPU ring buffer.
    typedef struct _ebpf_latency_ring_buffer
    {
        volatile uint32_t write_index;   // Only written by the owning CPU (at DISPATCH_LEVEL).
        volatile uint32_t dropped_count; // Records dropped (buffer full, overwrite not enabled).
        uint32_t next_correlation_id;    // Per-CPU correlation ID counter — plain increment.
        uint32_t records_count;          // Number of records in this ring buffer.

        // Padding to ensure the record array starts on a cache line boundary.
        uint8_t _padding[64 - 16];

        // The record array (variable length, allocated based on records_count).
        ebpf_latency_record_t records[1]; // Flexible array — actual size is records_count.
    } ebpf_latency_ring_buffer_t;

    // Global latency state.
    typedef struct _ebpf_latency_state
    {
        volatile long enabled;             // 0 = off, 1 = program only, 2 = program + helpers.
        volatile long session_active;      // 0 = no active session, 1 = session in progress.
        volatile long correlation_enabled; // 0 = no correlation IDs, 1 = generate per-invocation.
        uint32_t backend;                  // EBPF_LATENCY_BACKEND_RINGBUFFER or EBPF_LATENCY_BACKEND_ETW.

        // TSC calibration — captured once at enable time.
        uint64_t tsc_frequency; // TSC ticks per second.
        uint64_t tsc_at_enable; // rdtsc value at enable time.
        uint64_t qpc_at_enable; // QPC value at enable time (for ETW correlation).

        // Program ID filter list.
        uint32_t program_id_count;
        uint32_t program_ids[EBPF_LATENCY_MAX_PROGRAM_FILTER];

        // Per-CPU ring buffers. Allocated at enable, freed at disable.
        uint32_t cpu_count;
        uint32_t records_per_cpu;
        ebpf_latency_ring_buffer_t** per_cpu_buffers; // Array of pointers, one per CPU.
    } ebpf_latency_state_t;

    /**
     * @brief Get the current latency tracking mode.
     * @return Current latency mode (0=off, 1=program only, 2=program+helpers).
     */
    long
    ebpf_latency_get_mode();

    /**
     * @brief Check whether correlation IDs should be generated for each program invocation.
     * @retval TRUE if correlation IDs should be generated.
     * @retval FALSE if correlation IDs are disabled (correlation_id will be 0).
     */
    BOOLEAN
    ebpf_latency_is_correlation_enabled();

    /**
     * @brief Check whether a given program ID should be tracked.
     * @param[in] program_id The ID of the eBPF program to check.
     * @retval TRUE if the program should be tracked.
     * @retval FALSE if a filter is set and the program ID is not in the list.
     */
    BOOLEAN
    ebpf_latency_should_track_program(uint32_t program_id);

    /**
     * @brief Enable latency tracking with per-CPU ring buffers.
     * @param[in] mode Tracking mode: 1 = program only, 2 = program + helpers.
     * @param[in] flags Bitmask of EBPF_LATENCY_FLAG_* values.
     * @param[in] records_per_cpu Number of records per CPU ring buffer (0 = default).
     * @param[in] program_id_count Number of program IDs in the filter list (0 = track all).
     * @param[in] program_ids Optional array of program IDs to track.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_INVALID_ARGUMENT Invalid mode or records_per_cpu out of range.
     * @retval EBPF_INVALID_STATE Another latency tracking session is already active.
     * @retval EBPF_NO_MEMORY Failed to allocate ring buffers.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_latency_enable(
        uint32_t mode,
        uint32_t flags,
        uint32_t records_per_cpu,
        uint32_t program_id_count,
        _In_reads_opt_(program_id_count) const uint32_t* program_ids);

    /**
     * @brief Disable latency tracking (stop writes). Buffers remain for drain.
     * @retval EBPF_SUCCESS The operation was successful.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_latency_disable();

    /**
     * @brief Release the latency session and free all ring buffers.
     * Must be called after disable and drain are complete.
     * @retval EBPF_SUCCESS The operation was successful.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_latency_release();

    /**
     * @brief Write a latency record to the current CPU's ring buffer.
     *
     * Raises IRQL to DISPATCH_LEVEL if not already there, writes the record,
     * then restores IRQL.
     *
     * @param[in] program_id The eBPF program ID.
     * @param[in] helper_function_id BPF_FUNC_xxx (0 for program events).
     * @param[in] map_id Map ID (0 if not applicable).
     * @param[in] correlation_id Correlation ID (0 if not enabled).
     * @param[in] timestamp rdtsc timestamp.
     * @param[in] event_type EBPF_LATENCY_EVENT_* value.
     */
    void
    ebpf_latency_write_record(
        uint32_t program_id,
        uint16_t helper_function_id,
        uint16_t map_id,
        uint32_t correlation_id,
        uint64_t timestamp,
        uint8_t event_type);

    /**
     * @brief Generate the next per-CPU correlation ID.
     *
     * Must be called at DISPATCH_LEVEL or with IRQL raised to DISPATCH.
     *
     * @param[in] cpu The current processor number.
     * @return A unique correlation ID with CPU ID encoded in upper 8 bits.
     */
    uint32_t
    ebpf_latency_next_correlation_id(uint32_t cpu);

    /**
     * @brief Get the global latency state for drain operations.
     * @return Pointer to the global latency state (read-only for consumers).
     */
    const ebpf_latency_state_t*
    ebpf_latency_get_state();

#ifdef __cplusplus
}
#endif
