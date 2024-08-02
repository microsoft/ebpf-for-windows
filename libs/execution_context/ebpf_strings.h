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
_ebpf_core_strlen(_In_reads_(str_size) const char* str, size_t str_size);

int32_t
_ebpf_core_strcmp(
    _In_reads_(lhs_size) const char* lhs,
    size_t lhs_size,
    _In_reads_(rhs_size) const char* rhs,
    size_t rhs_size,
    size_t count);

char*
_ebpf_core_strchr(_In_reads_(str_size) const char* str, size_t str_size, char ch);

char*
_ebpf_core_strstr(
    _In_reads_(str_size) const char* str,
    size_t str_size,
    _In_reads_(substr_size) const char* substr,
    size_t substr_size);