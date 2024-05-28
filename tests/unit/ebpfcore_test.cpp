// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#include "catch_wrapper.hpp"
#include "device_helper.hpp"
#include "ebpf_protocol.h"
#include "usersim/wdf.h"

TEST_CASE("DriverEntry", "[usersim]")
{
    HMODULE module = LoadLibraryW(L"ebpfcore_usersim.dll");
    REQUIRE(module != nullptr);

    WDFDRIVER driver = usersim_get_driver_from_module(module);
    REQUIRE(driver != nullptr);

    WDFDEVICE device = usersim_get_device_by_name(driver, L"\\Device\\EbpfIoDevice");
    REQUIRE(device != nullptr);

    // Test an unrecognized IO control code.
    DWORD bytes_returned;
    BOOL ok = usersim_device_io_control(device, 0, nullptr, 0, nullptr, 0, &bytes_returned, nullptr);
    REQUIRE(!ok);

    // Unsupported input buffer size.
    ok = usersim_device_io_control(
        device, IOCTL_EBPF_CTL_METHOD_BUFFERED, nullptr, 0, nullptr, 0, &bytes_returned, nullptr);
    REQUIRE(!ok);

    // Make an actual call.
    ebpf_operation_get_next_id_request_t request;
    request.header.id = EBPF_OPERATION_GET_NEXT_PROGRAM_ID;
    request.header.length = sizeof(request);
    request.start_id = 0;
    ebpf_operation_get_next_id_reply_t reply;
    ok = usersim_device_io_control(
        device,
        IOCTL_EBPF_CTL_METHOD_BUFFERED,
        &request,
        sizeof(request),
        &reply,
        sizeof(reply),
        &bytes_returned,
        nullptr);
    REQUIRE(!ok);

    FreeLibrary(module);
}
