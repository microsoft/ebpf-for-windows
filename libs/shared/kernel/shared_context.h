// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#ifdef _DEBUG
#define ebpf_assert(x) ASSERT(x)
#else
#define ebpf_assert(x) (void)(x)
#endif // !_DEBUG
