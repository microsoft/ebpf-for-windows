// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include <ebpf_strings.h>
#include <ntstatus.h>
#pragma warning(push)
#pragma warning(disable : 28196) // There's a bad annotation in ntstrsafe.h that fails to validate
#include <ntstrsafe.h>
#pragma warning(pop)

errno_t
_ebpf_core_strncpy_s(
    _Out_writes_(dest_size) char* dest, size_t dest_size, _In_reads_(count) const char* src, size_t count)
{
    return RtlStringCbCopyNExA(dest, dest_size, src, count, NULL, NULL, STRSAFE_FILL_BEHIND_NULL | 0);
}

errno_t
_ebpf_core_strncat_s(
    _Out_writes_(dest_size) char* dest, size_t dest_size, _In_reads_(count) const char* src, size_t count)
{
    return RtlStringCbCatNExA(dest, dest_size, src, count, NULL, NULL, STRSAFE_FILL_BEHIND_NULL | 0);
}

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
