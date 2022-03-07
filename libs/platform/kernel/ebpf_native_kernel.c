// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// #include "ebpf_native.h"
#include "ebpf_result.h"
#include "ebpf_handle.h"
#include "framework.h"

ebpf_result_t
ebpf_native_load_module(_In_z_ const wchar_t* service_name)
{
    UNICODE_STRING driver_service_name;
    ebpf_result_t result = EBPF_SUCCESS;
    NTSTATUS status;

    RtlInitUnicodeString(&driver_service_name, service_name);
    status = ZwLoadDriver(&driver_service_name);
    if (status != STATUS_SUCCESS) {
        result = EBPF_FAILED;
    }

    return result;
}

void
ebpf_native_unload_module(_In_z_ const wchar_t* service_name)
{
    UNICODE_STRING driver_service_name;
    RtlInitUnicodeString(&driver_service_name, service_name);
    ZwUnloadDriver(&driver_service_name);
}
