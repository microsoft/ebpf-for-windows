// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

#include <errno.h>
#include <stdint.h>

errno_t
_ebpf_core_strcpy(
    _Out_writes_(dest_size) char* dest, size_t dest_size, _In_reads_(count) const char* src, size_t count);

errno_t
_ebpf_core_strcat(
    _Out_writes_(dest_size) char* dest, size_t dest_size, _In_reads_(count) const char* src, size_t count);

size_t
_ebpf_core_strlen_s(_In_reads_(str_size) const char* str, size_t str_size);
