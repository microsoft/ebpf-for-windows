// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once
#include <assert.h>

// Get definitions for ULONGLONG, etc.
#include <winsock2.h>
#include <windows.h>

#ifdef _DEBUG
#define ebpf_assert(x) assert(x)
#else
#define ebpf_assert(x) (void)(x)
#endif //!_DEBUG
