// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "ebpf_strings.h"

#include <stdlib.h>
#include <string.h>
#include <strsafe.h>

// errno_t bpf_strcpy(char *restrict dest, size_t dest_size, const char *restrict src, size_t src_count);
errno_t
_ebpf_core_strcpy(
    _Out_writes_(dest_size) char* dest, size_t dest_size, _In_reads_(src_count) const char* src, size_t src_count)
{
    return StringCbCopyNExA(dest, dest_size, src, src_count, NULL, NULL, STRSAFE_FILL_BEHIND_NULL | 0);
}

// errno_t bpf_strcat(char *restrict dest, size_t dest_size, const char *restrict src, size_t src_count);
errno_t
_ebpf_core_strcat(
    _Out_writes_(dest_size) char* dest, size_t dest_size, _In_reads_(src_count) const char* src, size_t src_count)
{
    return strncat_s(dest, dest_size, src, src_count);
}

// size_t bpf_strlen(const char *str, size_t str_size);
size_t
_ebpf_core_strlen_s(_In_reads_(str_size) const char* str, size_t str_size)
{
    return strnlen_s(str, str_size);
}
