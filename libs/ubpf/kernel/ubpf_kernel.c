// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define _CRT_SECURE_NO_WARNINGS 1

#include "ebpf_platform.h"

#pragma warning(disable : 4100)
#pragma warning(disable : 4018)
#pragma warning(disable : 4146)
#pragma warning(disable : 4214)
#pragma warning(disable : 4242)
#pragma warning(disable : 4244)
#pragma warning(disable : 4245)
#pragma warning(disable : 4267)

#include <stdlib.h>

#define malloc(X) ebpf_allocate((X))
#define calloc(X, Y) ebpf_allocate((X) * (Y))
#define free(X) ebpf_free(X)

#include <endian.h>
#include <unistd.h>

#if !defined(_countof)
#define _countof(_Array) (sizeof(_Array) / sizeof(_Array[0]))
#endif

#define stderr 0
#define fprintf NULL

#define UBPF_STACK_SIZE 512

#include "ubpf_vm.c"