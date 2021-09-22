// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#include "catch_wrapper.hpp"
#include "ebpf.h"
#include "ebpf_epoch.h"
#include "ebpf_core.h"
#include "ebpf_maps.h"
#include "ebpf_object.h"
#include "ebpf_program.h"
#include "helpers.h"
#include "libbpf.h"
#include "performance_measure.h"

#define PERF_TEST(FUNCTION)                                                               \
    TEST_CASE(#FUNCTION "_preemption", "[performance_" TEST_AREA "]") { FUNCTION(true); } \
    TEST_CASE(#FUNCTION "_no_preemption", "[performance_" TEST_AREA "]") { FUNCTION(false); }
