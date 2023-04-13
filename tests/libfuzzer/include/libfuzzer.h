// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifdef __cplusplus
#define FUZZ_EXPORT extern "C" __declspec(dllexport)
#else
#define FUZZ_EXPORT __declspec(dllexport)
#endif

#include "ebpf_watchdog_timer.h"