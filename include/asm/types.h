// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once
#include <stdint.h>
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef int16_t __s16;
typedef int32_t __s32;
typedef int64_t __s64;
#define __SIZEOF_LONG_LONG__ 8 /* only x64 is supported */
#define __SIZEOF_LONG__ 4      /* only x64 is supported */
