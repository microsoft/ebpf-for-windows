// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

#include "ebpf_object.h"

CXPLAT_EXTERN_C_BEGIN

// Test-private instrumentation, compiled only into the usersim runtime.
typedef enum _ebpf_object_test_point
{
    EBPF_OBJECT_TEST_BEFORE_PUBLICATION,
    EBPF_OBJECT_TEST_BEFORE_TRY_REFERENCE,
    EBPF_OBJECT_TEST_PIN_TABLE_ALLOCATION,
    EBPF_OBJECT_TEST_PIN_HASH_ALLOCATION,
    EBPF_OBJECT_TEST_PIN_ENTRY_ALLOCATION,
    EBPF_OBJECT_TEST_PIN_SNAPSHOT_ALLOCATION,
    EBPF_OBJECT_TEST_PIN_SNAPSHOT_PATH_ALLOCATION,
    EBPF_OBJECT_TEST_BEFORE_ASYNC_CANCEL,
} ebpf_object_test_point_t;

typedef bool (*ebpf_object_test_callback_t)(
    ebpf_object_test_point_t point, _In_opt_ const ebpf_core_object_t* object, _Inout_opt_ void* context);

// Install and remove callbacks only while no instrumented operations are running.
// Returning true injects allocation failure; publication/reference/cancellation callbacks must return false.
void
ebpf_object_test_set_callback(_In_opt_ ebpf_object_test_callback_t callback, _Inout_opt_ void* context);

bool
ebpf_object_test_invoke(ebpf_object_test_point_t point, _In_opt_ const ebpf_core_object_t* object);

struct _ebpf_pinning_table;
void
ebpf_pinning_table_test_set_cookie_counter(_Inout_ struct _ebpf_pinning_table* table, uint64_t value);

CXPLAT_EXTERN_C_END
