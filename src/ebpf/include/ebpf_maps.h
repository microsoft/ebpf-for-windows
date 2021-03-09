/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */
#pragma once
#include "ebpf_platform.h"
#include "ebpf_windows.h"
#include "pch.h"

typedef struct _ebpf_core_map {
  struct _ebpf_map_definition ebpf_map_definition;
  ebpf_lock_t lock;
  uint8_t *data;
} ebpf_core_map_t;

typedef struct _ebpf_map_function_table {
  ebpf_core_map_t *(*create_map)(
      _In_ const ebpf_map_definition_t *map_definition);
  void (*delete_map)(_In_ ebpf_core_map_t *map);
  uint8_t *(*lookup_entry)(_In_ ebpf_core_map_t *map, _In_ const uint8_t *key);
  ebpf_error_code_t (*update_entry)(_In_ ebpf_core_map_t *map,
                                    _In_ const uint8_t *key,
                                    _In_ const uint8_t *value);
  ebpf_error_code_t (*delete_entry)(_In_ ebpf_core_map_t *map,
                                    _In_ const uint8_t *key);
  ebpf_error_code_t (*next_key)(_In_ ebpf_core_map_t *map,
                                _In_ const uint8_t *previous_key,
                                _Out_ uint8_t *next_key);
} ebpf_map_function_table_t;

extern ebpf_map_function_table_t
    ebpf_map_function_tables[EBPF_MAP_TYPE_ARRAY + 1];