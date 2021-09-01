// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Common test functions used by end to end and component tests.

#pragma once
#include <windows.h>

#include "bpf.h"
#include "ebpf_api.h"
#include "ebpf_result.h"
#include "libbpf.h"

#pragma warning(disable : 26812) // Prefer enum class.

void
ebpf_test_pinned_map_enum();

void
verify_utility_helper_results(_In_ const bpf_object* object);
