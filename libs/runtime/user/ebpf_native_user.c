// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "ebpf_result.h"
#include "framework.h"

_Must_inspect_result_ ebpf_result_t
ebpf_native_load_driver(_In_z_ const wchar_t* service_name)
{
    UNREFERENCED_PARAMETER(service_name);
    return EBPF_OPERATION_NOT_SUPPORTED;
}

void
ebpf_native_unload_driver(_In_z_ const wchar_t* service_name)
{
    UNREFERENCED_PARAMETER(service_name);
}
