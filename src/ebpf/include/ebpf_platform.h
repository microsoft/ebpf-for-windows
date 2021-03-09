/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef enum _ebpf_memory_type {
  EBPF_MEMORY_NO_EXECUTE = 0,
  EBPF_MEMORY_EXECUTE = 1,
} ebpf_memory_type_t;

typedef enum _ebpf_code_integrity_state {
  EBPF_CODE_INTEGRITY_DEFAULT = 0,
  EBPF_CODE_INTEGRITY_HYPER_VISOR_KERNEL_MODE = 1
} ebpf_code_integrity_state_t;

void *ebpf_allocate(size_t size, ebpf_memory_type_t type);
void ebpf_free(void *memory);

ebpf_error_code_t
ebpf_query_code_integrity_state(ebpf_code_integrity_state_t *state);

#define EBPF_LOCK_SIZE sizeof(uint64_t)
#define EBPF_LOCK_STATE_SIZE sizeof(uint64_t)
ebpf_error_code_t ebpf_safe_size_t_multiply(size_t multiplicand,
                                            size_t multiplier, size_t *result);
ebpf_error_code_t ebpf_safe_size_t_add(size_t augend, size_t addend,
                                       size_t *result);

typedef uint8_t ebpf_lock_t[EBPF_LOCK_SIZE];
typedef uint8_t ebpf_lock_state_t[EBPF_LOCK_STATE_SIZE];

void ebpf_lock_create(ebpf_lock_t *lock);
void ebpf_lock_destroy(ebpf_lock_t *lock);
void ebpf_lock_lock(ebpf_lock_t *lock, ebpf_lock_state_t *state);
void ebpf_lock_unlock(ebpf_lock_t *lock, ebpf_lock_state_t *state);

typedef struct _ebpf_hash_table ebpf_hash_table_t;

ebpf_error_code_t ebpf_hash_table_create(ebpf_hash_table_t **hash_table,
                                         size_t key_size, size_t value_size);
void ebpf_hash_table_destroy(ebpf_hash_table_t *hash_table);
ebpf_error_code_t ebpf_hash_table_lookup(ebpf_hash_table_t *hash_table,
                                         const uint8_t *key, uint8_t **value);
ebpf_error_code_t ebpf_hash_table_update(ebpf_hash_table_t *hash_table,
                                         const uint8_t *key,
                                         const uint8_t *value);
ebpf_error_code_t ebpf_hash_table_delete(ebpf_hash_table_t *hash_table,
                                         const uint8_t *key);
ebpf_error_code_t ebpf_hash_table_next_key(ebpf_hash_table_t *hash_table,
                                           const uint8_t *previous_key,
                                           uint8_t *next_key);

#ifdef __cplusplus
}
#endif
