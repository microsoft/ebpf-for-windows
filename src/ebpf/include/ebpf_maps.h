/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */
#pragma once

#include "ebpf_platform.h"

typedef struct _ebpf_core_map ebpf_map_t;

ebpf_error_code_t
ebpf_map_create(const ebpf_map_definition_t* ebpf_map_definition, ebpf_map_t** map);

void
ebpf_map_acquire_reference(ebpf_map_t* map);

void
ebpf_map_release_reference(ebpf_map_t* map);

ebpf_map_definition_t*
ebpf_map_get_definition(ebpf_map_t* map);

uint8_t*
ebpf_map_lookup_entry(ebpf_map_t* map, const uint8_t* key);

ebpf_error_code_t
ebpf_map_update_entry(ebpf_map_t* map, const uint8_t* key, const uint8_t* value);

ebpf_error_code_t 
ebpf_map_delete_entry(ebpf_map_t* map, const uint8_t* key);

ebpf_error_code_t
ebpf_map_next_key(ebpf_map_t* map, const uint8_t* previous_key, uint8_t* next_key);
