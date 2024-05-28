/*
 *  Copyright (c) eBPF for Windows contributors
 *  SPDX-License-Identifier: MIT
 */

#pragma once
#include "ebpf_shared_framework.h"

#define PROT_READ 0
#define PROT_WRITE 0
#define MAP_PRIVATE 0
#define MAP_ANONYMOUS 0
#define MAP_FAILED NULL
#define PROT_EXEC 0

void*
mmap(void* addr, size_t length, int prot, int flags, int fd, size_t offset)
{
    ebpf_assert(false);
    return NULL;
}

int
munmap(void* addr, size_t length)
{
    ebpf_assert(false);
    return 0;
}

int
mprotect(void* addr, size_t len, int prot)
{
    ebpf_assert(false);
    return 0;
}
