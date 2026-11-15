// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

#include "ebpf_native.h"

CXPLAT_EXTERN_C_BEGIN

typedef enum _ebpf_native_test_point
{
    EBPF_NATIVE_TEST_LOADING_UNLOCKED,
    EBPF_NATIVE_TEST_MAP_ALLOCATION,
    EBPF_NATIVE_TEST_MAP_PINNED,
    EBPF_NATIVE_TEST_PROGRAM_ALLOCATION,
    EBPF_NATIVE_TEST_PROGRAM_CREATED,
    EBPF_NATIVE_TEST_INITIAL_VALUE,
} ebpf_native_test_point_t;

typedef struct _ebpf_native_test_event
{
    GUID module_id;
    GUID namespace_id;
    size_t index;
    ebpf_handle_t handle;
    const char* name;
} ebpf_native_test_event_t;

typedef bool (*ebpf_native_test_callback_t)(
    ebpf_native_test_point_t point, _In_ const ebpf_native_test_event_t* event, _Inout_opt_ void* context);

// Usersim-only. Change callbacks only when no instrumented loads are running.
// Callback event storage is borrowed for the duration of the callback.
void
ebpf_native_test_set_callback(_In_opt_ ebpf_native_test_callback_t callback, _Inout_opt_ void* context);

typedef enum _ebpf_native_test_state
{
    EBPF_NATIVE_TEST_UNINITIALIZED,
    EBPF_NATIVE_TEST_INITIALIZING,
    EBPF_NATIVE_TEST_INITIALIZED,
    EBPF_NATIVE_TEST_LOADING,
    EBPF_NATIVE_TEST_LOADED,
    EBPF_NATIVE_TEST_UNLOADING,
} ebpf_native_test_state_t;

typedef struct _ebpf_native_test_snapshot
{
    ebpf_native_test_state_t state;
    bool detaching;
    bool transient_override;
    int64_t references;
} ebpf_native_test_snapshot_t;

typedef enum _ebpf_native_test_transient_state
{
    EBPF_NATIVE_TEST_TRANSIENT_UNLOADING,
    EBPF_NATIVE_TEST_TRANSIENT_DETACHING,
} ebpf_native_test_transient_state_t;

_Must_inspect_result_ ebpf_result_t
ebpf_native_test_get_snapshot(_In_ const GUID* module_id, _Out_ ebpf_native_test_snapshot_t* snapshot);

// Only an INITIALIZED module can be overridden. The next rejected load restores
// the saved fields under its module lock, before entering public-load cleanup.
_Must_inspect_result_ ebpf_result_t
ebpf_native_test_override_state(_In_ const GUID* module_id, ebpf_native_test_transient_state_t state);

_Must_inspect_result_ ebpf_result_t
ebpf_native_test_restore_state(_In_ const GUID* module_id);

CXPLAT_EXTERN_C_END
