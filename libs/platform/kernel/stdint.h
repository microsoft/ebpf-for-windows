// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <basetsd.h>
typedef INT8 int8_t;
typedef INT16 int16_t;
typedef INT32 int32_t;
typedef INT64 int64_t;

typedef UINT8 uint8_t;
typedef UINT16 uint16_t;
typedef UINT32 uint32_t;
typedef UINT64 uint64_t;

#ifdef _WIN64
typedef __int64 intptr_t;
#else
typedef _W64 int intptr_t;
#endif