// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once
#include <ntifs.h> // Must be included before ntddk.h
#include <ntddk.h>

#ifdef _DEBUG
#define ebpf_assert(x) ASSERT(x)
#else
#define ebpf_assert(x) (void)(x)
#endif // !_DEBUG
