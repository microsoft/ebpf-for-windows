// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Include framework.h to capture the platform specific Windows headers.
// Required by bcrypt.h.
#include "framework.h"

#include <bcrypt.h>
#pragma comment(lib, "bcrypt")
#include "ebpf_platform.h"

// This file contains the wrapper around the crypto API.

typedef struct _ebpf_cryptographic_hash
{
    BCRYPT_ALG_HANDLE algorithm_handle;
    BCRYPT_HASH_HANDLE hash_handle;
} ebpf_cryptographic_hash_t;

_Must_inspect_result_ ebpf_result_t
ebpf_cryptographic_hash_create(_In_z_ const wchar_t* algorithm, _Outptr_ ebpf_cryptographic_hash_t** hash)
{
    ebpf_result_t result;
    NTSTATUS nt_status;
    ebpf_cryptographic_hash_t* local_hash =
        (ebpf_cryptographic_hash_t*)ebpf_allocate(sizeof(ebpf_cryptographic_hash_t));
    if (local_hash == NULL) {
        result = EBPF_NO_MEMORY;
        goto Done;
    }

    memset(local_hash, 0, sizeof(ebpf_cryptographic_hash_t));

    nt_status = BCryptOpenAlgorithmProvider(&local_hash->algorithm_handle, algorithm, NULL, 0);
    if (!NT_SUCCESS(nt_status)) {
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    nt_status = BCryptCreateHash(local_hash->algorithm_handle, &local_hash->hash_handle, NULL, 0, NULL, 0, 0);
    if (!NT_SUCCESS(nt_status)) {
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    result = EBPF_SUCCESS;
    *hash = local_hash;
    local_hash = NULL;
Done:
    ebpf_cryptographic_hash_destroy(local_hash);
    local_hash = NULL;
    return result;
}

// SAL annotation must be _In_opt_ as this function looks inside the structure to free entries.
void
ebpf_cryptographic_hash_destroy(_In_opt_ _Frees_ptr_opt_ ebpf_cryptographic_hash_t* hash)
{
    if (hash) {
        if (hash->hash_handle) {
            BCryptDestroyHash(hash->hash_handle);
        }
        if (hash->algorithm_handle) {
            BCryptCloseAlgorithmProvider(hash->algorithm_handle, 0);
        }
        ebpf_free(hash);
    }
}

_Must_inspect_result_ ebpf_result_t
ebpf_cryptographic_hash_append(
    _Inout_ ebpf_cryptographic_hash_t* hash, _In_reads_bytes_(length) const uint8_t* buffer, size_t length)
{
    NTSTATUS nt_status;

    nt_status = BCryptHashData(hash->hash_handle, (uint8_t*)buffer, (ULONG)length, 0);
    if (!NT_SUCCESS(nt_status)) {
        return EBPF_INVALID_ARGUMENT;
    }
    return EBPF_SUCCESS;
}

_Must_inspect_result_ ebpf_result_t
ebpf_cryptographic_hash_get_hash(
    _Inout_ ebpf_cryptographic_hash_t* hash,
    _Out_writes_to_(input_length, *output_length) uint8_t* buffer,
    size_t input_length,
    _Out_ size_t* output_length)
{
    NTSTATUS nt_status;
    unsigned long property_length;
    nt_status = BCryptGetProperty(
        hash->hash_handle, BCRYPT_HASH_LENGTH, (PUCHAR)output_length, sizeof(*output_length), &property_length, 0);
    if (!NT_SUCCESS(nt_status)) {
        return EBPF_INVALID_ARGUMENT;
    }

    if ((*output_length > input_length) || (*output_length > UINT32_MAX)) {
        return EBPF_INSUFFICIENT_BUFFER;
    }

    nt_status = BCryptFinishHash(hash->hash_handle, buffer, (ULONG)*output_length, 0);
    if (!NT_SUCCESS(nt_status)) {
        return EBPF_INVALID_ARGUMENT;
    }

    return EBPF_SUCCESS;
}
