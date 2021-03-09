// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#if defined(NTDDI_VERSION)
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
#endif

// This file contains eBPF definitions needed by eBPF programs as well as
// the verifier and execution context.

typedef enum _ebpf_map_type {
  EBPF_MAP_TYPE_UNSPECIFIED = 0,
  EBPF_MAP_TYPE_HASH = 1,
  EBPF_MAP_TYPE_ARRAY = 2,
} ebpf_map_type_t;

typedef enum ebpf_program_type {
  EBPF_PROGRAM_TYPE_UNSPECIFIED = 0,
  EBPF_PROGRAM_TYPE_XDP = 1,
  EBPF_PROGRAM_TYPE_BIND = 2
} ebpf_program_type_t;

typedef enum _ebpf_helper_function {
  EBPF_LOOKUP_ELEMENT = 1,
  EBPF_UPDATE_ELEMENT = 2,
  EBPF_DELETE_ELEMENT = 3,
} ebpf_helper_function_t;

typedef enum _ebpf_error_code {
  EBPF_ERROR_SUCCESS,
  EBPF_ERROR_OUT_OF_RESOURCES,
  EBPF_ERROR_NOT_FOUND,
  EBPF_ERROR_INVALID_PARAMETER,
  EBPF_ERROR_BLOCKED_BY_POLICY,
  EBPF_ERROR_NO_MORE_KEYS,
  EBPF_ERROR_INVALID_HANDLE,
  EBPF_ERROR_NOT_SUPPORTED
} ebpf_error_code_t;

typedef struct _ebpf_map_definition {
  uint32_t size;
  uint32_t type;
  uint32_t key_size;
  uint32_t value_size;
  uint32_t max_entries;
} ebpf_map_definition_t;
