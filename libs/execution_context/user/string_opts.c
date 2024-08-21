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

// int bpf_strcmp(const char *lhs, size_t lhs_size, const char *rhs, size_t rhs_size, size_t count);
int32_t
_ebpf_core_strcmp(
    _In_reads_(lhs_size) const char* lhs,
    uint32_t lhs_size,
    _In_reads_(rhs_size) const char* rhs,
    uint32_t rhs_size,
    uint32_t count)
{
    // Minor issue: strncmp() takes three arguments: lhs, rhs, len. The length is the number of characters to compare.

    // strncmp() does the following:
    // strncmp("Hello, world!", "Hello", 5) = 0
    // strncmp("Hello, world!", "Hell\0", 5) > 0
    // strncmp("Hello, world!", "Hey", 5) < 0

    // Basically, it feels like if it's equal at a shorter length, the longer string gets the nod.

    // Being cognizant that either or both lhs and rhs might not be null-terminated, we can use the minimum length bound
    // of any of them to establish what is the "safe" number of characters to use for the string check.
    size_t min_size = __min(lhs_size, rhs_size);
    size_t min_count = __min(min_size, count);

    int compare = strncmp(lhs, rhs, min_count);
    // However, the output of strncmp isn't the only story. If compare == 0, we should also consider if min_count is
    // the correct bound to stop at.
    if (compare == 0 && min_count < count) {
        // If min_count < count, then we're going to need to validate which string actually is longer--and how.
        size_t lhs_len = strnlen_s(lhs, lhs_size);
        size_t rhs_len = strnlen_s(rhs, rhs_size);

        // lhs_len <= lhs_size; rhs_len <= rhs_size, meanwhile min_count <= lhs_size and min_count <= rhs_size.
        // Now we get to sort out how lhs_len and rhs_len and min_count apply to each other.
        // In all of these cases, the longer string wins. The only question is, are any of the strings longer than the
        // other
        // if min_count <= min(lhs_len, rhs_len): nothing to do.
        // if lhs_len < min_count <= rhs_len: return -1
        if (lhs_len < rhs_len && lhs_len < min_count) {
            return -1;
        }
        // if rhs_len < min_count <= lhs_len: return 1
        if (rhs_len < lhs_len && rhs_len < min_count) {
            return 1;
        }
    }

    return compare;
}

// char *bpf_strchr(const char *str, size_t str_size, char ch);
char*
_ebpf_core_strchr(_In_reads_(str_size) const char* str, size_t str_size, char ch)
{
    size_t str_len = strnlen_s(str, str_size);
    if (str_len == str_size) {
        // There is no null termination in the buffer, and we should use memchr to search instead.
        return memchr(str, ch, str_size);
    }

    // Otherwise, if a null termination was found, use strchr, since str_len will not include the null termination,
    // and the terminal null is considered part of the string.
    return strchr(str, ch);
}

// char *bpf_strstr(const char *str, size_t str_size, const char *substr, size_t substr_size);
char*
_ebpf_core_strstr(
    _In_reads_(str_size) const char* str,
    size_t str_size,
    _In_reads_(substr_size) const char* substr,
    size_t substr_size)
{
    (void)str_size;
    (void)substr_size;
    // check string lengths first
    return strstr(str, substr);
}

// long bpf_strtol(const char *str, unsigned long str_len, uint64_t flags, long *res); // Note
long
_ebpf_core_strtol(_In_reads_(str_size) const char* str, size_t str_size, uint64_t flags, _Out_ long* result)
{
    // Much as with strtoul below, this will need RtlCharToInteger for kernel mode.
    // It almost feels like this function should be implemented in different bodies for kernel
    // and user modes, they're going to have such different behaviors.

    long value = 0;
    int base = (int)(0x1F & flags); // We take five bits for base
    char* num_end = NULL;

    if (result == NULL) {
        return -EINVAL;
    }

    *result = 0;

    // - validate that str is null-terminated
    if (strnlen_s(str, str_size) == str_size) {
        // str is not null-terminated.
        return -EINVAL;
    }

    // - validate that base is one of the supported values:
    if (base != 0 && base != 8 && base != 10 && base != 16) {
        return -EINVAL;
    }

    errno = 0;
    value = strtol(str, &num_end, base);

    if (errno == ERANGE) {
        // exceeded range
        return -ERANGE;
    }

    *result = value;
    return (long)(num_end - str);
}

// long bpf_strtoul(const char *str, unsigned long str_len, uint64_t flags, unsigned long *res); // Note
long
_ebpf_core_strtoul(_In_reads_(str_size) const char* str, size_t str_size, uint64_t flags, _Out_ unsigned long* result)
{
    // This one's going to need RtlCharToInteger for the kernel code, UM code can make use of strtoul.
    // The Windows kernel APIs are really inconsistent about their ANSI/Unicode support, so you only
    // have RtlUnicodeToInteger, but we're working with ANSI strings, and upconverting a random ANSI
    // string to Unicode internally just to parse a number feels like way too much work.

    (void)str_size;
    int64_t value = 0;

    int base = (int)(0x1F & flags);
    char* num_end = NULL;

    if (result == NULL) {
        return -EINVAL;
    }

    *result = 0;

    // - validate that base is one of the supported values:
    if (base != 0 && base != 8 && base != 10 && base != 16) {
        return -EINVAL;
    }

    errno = 0;

    value = strtoul(str, &num_end, base);

    if (errno == ERANGE) {
        return -ERANGE;
    }

    *result = (unsigned long)value;
    return (long)(num_end - str);
}
