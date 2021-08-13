// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_platform.h"

extern "C"
{

    // The _In_ on size is necessary to avoid inconsistent annotation warnings.
    _Must_inspect_result_ _Ret_maybenull_ _Post_writable_byte_size_(size) void* __RPC_USER
        MIDL_user_allocate(_In_ size_t size)
    {
        return ebpf_allocate(size);
    }

    void __RPC_USER
    MIDL_user_free(_Pre_maybenull_ _Post_invalid_ void* p)
    {
        ebpf_free(p);
    }
}