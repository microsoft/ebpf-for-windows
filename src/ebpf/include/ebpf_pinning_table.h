/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */
#pragma once
#include "ebpf_object.h"
#include "ebpf_platform.h"

#ifdef __cplusplus
extern "C"
{
#endif
    typedef struct _ebpf_pinning_table ebpf_pinning_table_t;

    ebpf_error_code_t
    ebpf_pinning_table_allocate(ebpf_pinning_table_t** pinning_table);

    void
    ebpf_pinning_table_free(ebpf_pinning_table_t* pinning_table);

    ebpf_error_code_t
    ebpf_pinning_table_insert(ebpf_pinning_table_t* pinning_table, const uint8_t* name, ebpf_object_t* object);

    ebpf_error_code_t
    ebpf_pinning_table_lookup(ebpf_pinning_table_t* pinning_table, const uint8_t* name, ebpf_object_t** object);

    ebpf_error_code_t
    ebpf_pinning_table_delete(ebpf_pinning_table_t* pinning_table, const uint8_t* name);

#ifdef __cplusplus
}
#endif
