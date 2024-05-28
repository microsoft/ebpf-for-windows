// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "ebpf_handle.h"
#include "ebpf_tracelog.h"

_Must_inspect_result_ ebpf_result_t
ebpf_native_load_driver(_In_z_ const wchar_t* service_name)
{
    UNICODE_STRING driver_service_name;
    ebpf_result_t result = EBPF_SUCCESS;
    NTSTATUS status;

    RtlInitUnicodeString(&driver_service_name, service_name);
    status = ZwLoadDriver(&driver_service_name);
    EBPF_LOG_NTSTATUS_WSTRING_API(EBPF_TRACELOG_KEYWORD_NATIVE, service_name, ZwLoadDriver, status);
    if (status != STATUS_SUCCESS) {
        result = EBPF_FAILED;
    }

    return result;
}

void
ebpf_native_unload_driver(_In_z_ const wchar_t* service_name)
{
    NTSTATUS status;
    UNICODE_STRING driver_service_name;
    RtlInitUnicodeString(&driver_service_name, service_name);
    status = ZwUnloadDriver(&driver_service_name);
    EBPF_LOG_NTSTATUS_WSTRING_API(EBPF_TRACELOG_KEYWORD_NATIVE, service_name, ZwUnloadDriver, status);
}
