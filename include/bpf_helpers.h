// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

// On Linux, including the bpf_helpers.h in libbpf must be done after including
// a platform-specific include file such as vmlinux.h or linux/types.h which makes
// it not quite platform-agnostic today.  We hope this to change in the future
// once libbpf itself becomes cross-platform (issue #351).  In the meantime,
// this version of bpf_helpers.h is already cross-platform.

// Include platform-specific definitions.
#include "bpf_helpers_platform.h"
#include "ebpf_structs.h"

// If we're compiling an actual eBPF program, then include
// libbpf's bpf_helpers.h for the rest of the platform-agnostic
// defines.
#ifndef _MSC_VER

// Definitions lifted from libbpf's bpf_helpers.h.
// Moved here to avoid including libbpf's bpf_helpers.h as that file
// is not cross-platform.

#define __uint(name, val) int(*name)[val]
#define __type(name, val) typeof(val)* name
#define __array(name, val) typeof(val)* name[]

/*
 * Helper macro to place programs, maps, license in
 * different sections in elf_bpf file. Section names
 * are interpreted by libbpf depending on the context (BPF programs, BPF maps,
 * extern variables, etc).
 * To allow use of SEC() with externs (e.g., for extern .maps declarations),
 * make sure __attribute__((unused)) doesn't trigger compilation warning.
 */
#if __GNUC__ && !__clang__

/*
 * Pragma macros are broken on GCC
 * https://gcc.gnu.org/bugzilla/show_bug.cgi?id=55578
 * https://gcc.gnu.org/bugzilla/show_bug.cgi?id=90400
 */
#define SEC(name) __attribute__((section(name), used))

#else

#define SEC(name)                                                                             \
    _Pragma("GCC diagnostic push") _Pragma("GCC diagnostic ignored \"-Wignored-attributes\"") \
        __attribute__((section(name), used)) _Pragma("GCC diagnostic pop")

#endif

#ifndef NULL
#define NULL ((void*)0)
#endif

#define bpf_map_def _ebpf_map_definition_in_file
#include "ebpf_nethooks.h"
#endif

#ifndef __doxygen
#define EBPF_HELPER(return_type, name, args) typedef return_type(*name##_t) args
#endif

#include "bpf_helper_defs.h"

#ifndef _WIN32
#define _WIN32
#endif
