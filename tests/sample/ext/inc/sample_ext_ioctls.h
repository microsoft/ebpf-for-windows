// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/**
 * @brief Header file for the test eBPF extension driver's device IOCTLs.
 */

#pragma once

#define SAMPLE_EBPF_EXT_DEVICE_WIN32_NAME L"\\\\.\\SampleEbpfExtIoDevice"

//
// IOCTL Codes
//

#define IOCTL_SAMPLE_EBPF_EXT_CTL CTL_CODE(FILE_DEVICE_NETWORK, 0x0, METHOD_BUFFERED, FILE_ANY_ACCESS)
