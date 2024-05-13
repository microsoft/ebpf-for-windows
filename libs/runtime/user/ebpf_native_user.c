// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "ebpf_result.h"
#include "framework.h"

void
unload_native_module(_In_z_ const wchar_t* service_name);

ebpf_result_t
ZwLoadDriver(_In_z_ const wchar_t* DriverServiceName);
ebpf_result_t
ZwUnloadDriver(_In_z_ const wchar_t* DriverServiceName);

_Must_inspect_result_ ebpf_result_t
ebpf_native_load_driver(_In_z_ const wchar_t* service_name)
{
    // UNREFERENCED_PARAMETER(service_name);
    // return EBPF_OPERATION_NOT_SUPPORTED;
    return ZwLoadDriver(service_name);
}

void
ebpf_native_unload_driver(_In_z_ const wchar_t* service_name)
{
    ZwUnloadDriver(service_name);
    // unload_native_module(service_name);
    // UNREFERENCED_PARAMETER(service_name);
}
