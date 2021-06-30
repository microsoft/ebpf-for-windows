// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/*++

Abstract:

   Header file for test eBPF extension driver's device IOCTLs.

Environment:

    Kernel mode

--*/

#pragma once

#define TEST_EBPF_EXT_DEVICE_WIN32_NAME L"\\\\.\\TestEbpfExtIoDevice"

//
// IOCTL Codes
//

#define IOCTL_TEST_EBPF_EXT_CTL CTL_CODE(FILE_DEVICE_NETWORK, 0x0, METHOD_BUFFERED, FILE_ANY_ACCESS)
