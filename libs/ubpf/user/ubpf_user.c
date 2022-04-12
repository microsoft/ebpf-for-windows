// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define _CRT_SECURE_NO_WARNINGS 1

#include "ebpf_platform.h"

#pragma warning(disable : 4013)
#pragma warning(disable : 4018)
#pragma warning(disable : 4090)
#pragma warning(disable : 4146)
#pragma warning(disable : 4214)
#pragma warning(disable : 4242)
#pragma warning(disable : 4244)
#pragma warning(disable : 4245)
#pragma warning(disable : 4267)

#include <endian.h>
#define UBPF_STACK_SIZE 512

#pragma warning(push)
#pragma warning(disable : 6387) // ubpf_jit.c(70): error C6387: 'buffer' could be '0'
#include "ubpf_jit.c"
#include "ubpf_jit_x86_64.c"
#pragma warning(pop)
#include "ubpf_vm.c"