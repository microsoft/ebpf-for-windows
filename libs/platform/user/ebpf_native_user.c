// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_result.h"
#include "framework.h"

ebpf_result_t
ebpf_native_load_driver(_In_z_ const wchar_t* service_name)
{
    UNREFERENCED_PARAMETER(service_name);
    return EBPF_SUCCESS;
}

void
ebpf_native_unload_driver(_In_z_ const wchar_t* service_name)
{
    UNREFERENCED_PARAMETER(service_name);
}
