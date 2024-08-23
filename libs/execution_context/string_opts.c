// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include <ebpf_strings.h>

#include <ntstatus.h>
#include <Ntstrsafe.h>

/*
long
_ebpf_core_strtol(_In_reads_(str_size) const char* str, size_t str_size, uint64_t flags, _Out_ long* result);

long
_ebpf_core_strtoul(_In_reads_(str_size) const char* str, size_t str_size, uint64_t flags, _Out_ unsigned long* result);
*/

// errno_t bpf_strcpy(char *restrict dest, size_t dest_size, const char *restrict src, size_t count);
errno_t
_ebpf_core_strncpy_s(_Out_writes_(dest_size) char* dest, size_t dest_size, _In_reads_(count) const char* src, size_t count)
{
    return RtlStringCbCopyNExA(dest, dest_size, src, count, NULL, NULL, STRSAFE_FILL_BEHIND_NULL | 0);
}

// errno_t bpf_strcat(char *restrict dest, size_t dest_size, const char *restrict src, size_t count);
errno_t
_ebpf_core_strncat_s(_Out_writes_(dest_size) char* dest, size_t dest_size, _In_reads_(count) const char* src, size_t count)
{
    return strncat_s(dest, dest_size, src, count);
}

// size_t bpf_strlen(const char *str, size_t str_size);
size_t
_ebpf_core_strlen_s(_In_reads_(str_size) const char* str, size_t str_size)
{
    size_t length = 0;

    NTSTATUS Status = RtlStringCbLengthA(str, str_size, &length);

    if (NT_ERROR(Status)) {
        if (str == NULL) {
            // Null pointer: return 0.
            return 0;
        }

        // no null found; match the behavior of strlen_s and return the buffer length.
        return str_size;
    }

    return length;
}
