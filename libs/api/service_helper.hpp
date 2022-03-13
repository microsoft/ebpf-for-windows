// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "framework.h"

// #include <fcntl.h>
// #include <io.h>
#include <mutex>

// #include "api_internal.h"
// #include "bpf.h"
// #include "device_helper.hpp"
// #include "ebpf_api.h"
// #include "ebpf_platform.h"
// #include "ebpf_protocol.h"
// #include "ebpf_ring_buffer.h"
// #include "ebpf_serialize.h"

std::wstring
guid_to_wide_string(GUID* guid);

ebpf_result_t
create_service(
    _In_ const wchar_t* service_name, _In_ const wchar_t* file_path, bool kernel_mode, _Out_ SC_HANDLE* service_handle);

ebpf_result_t
delete_service(SC_HANDLE service_handle);