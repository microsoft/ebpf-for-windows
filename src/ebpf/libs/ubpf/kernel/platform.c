/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#include <ntddk.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

void *ubpf_alloc(size_t size, size_t count) {
  void *memory = ExAllocatePool(POOL_FLAG_NON_PAGED, size * count);
  if (memory) {
    memset(memory, 0, size * count);
  }
  return memory;
}

void ubpf_free(void *memory) { ExFreePool(memory); }

int vasprintf(char **target, const char *format, va_list argptr) {
  int length = 1024;
  *target = ubpf_alloc(length, sizeof(const char));
  return vsprintf_s(*target, length, format, argptr);
}
