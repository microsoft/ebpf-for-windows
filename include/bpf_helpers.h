// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

// Include platform-specific definitions.
#include "bpf_helpers_platform.h"
#include "ebpf_structs.h"

#if !defined(_MSVC_VER)

// BTF macros recreated from Linux kernel docs and dumping the BTF of the
// compiled ELF files.
//
// __uint and __type
// https://www.kernel.org/doc/html/latest/bpf/btf.html
// __array
// https://www.kernel.org/doc/html/next/bpf/map_of_maps.html

/**
 * @brief Declare a field with a given size in a BPF map.
 */
#define __uint(field_name, field_value) int(*field_name)[field_value]

/**
 * @brief Declare a field with a given type in a BPF map.
 */
#define __type(field_name, field_type) typeof(field_type)* field_name

/**
 * @brief Declare the value in a BPF map of type map-in-map or program-in-map.
 */
#define __array(field_name, map_template) typeof(map_template)* field_name[]

// SEC macro recreated from LLVM docs:
// https://clang.llvm.org/docs/AttributeReference.html

/**
 * @brief LLVM attribute to place a variable in a specific ELF section.
 */
#define SEC(NAME) __attribute__((section(NAME)))

#define bpf_map_def _ebpf_map_definition_in_file
#include "ebpf_nethooks.h"

#endif

#if !defined(NULL)
#define NULL ((void*)0)
#endif

#if !defined(__doxygen)
#define EBPF_HELPER(return_type, name, args) typedef return_type(*const name##_t) args
#endif

#include "bpf_helper_defs.h"

#if !defined(_WIN32)
#define _WIN32
#endif
