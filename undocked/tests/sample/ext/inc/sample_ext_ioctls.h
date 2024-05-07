// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

/**
 * @brief Header file for the sample eBPF extension driver's device IOCTLs.
 */

#pragma once

#define SAMPLE_EBPF_EXT_NAME_A "SampleEbpfExt"

#define WIDEN2(x) L##x
#define WIDEN(x) WIDEN2(x)
#define SAMPLE_EBPF_EXT_NAME_W WIDEN(SAMPLE_EBPF_EXT_NAME_A)
#define SAMPLE_EBPF_EXT_DEVICE_BASE_NAME SAMPLE_EBPF_EXT_NAME_W L"IoDevice"
#define SAMPLE_EBPF_EXT_DEVICE_WIN32_NAME L"\\\\.\\" SAMPLE_EBPF_EXT_DEVICE_BASE_NAME

//
// IOCTL Codes
//

typedef enum _sample_ebpf_ext_control_code
{
    SAMPLE_EBPF_EXT_CONTROL_RUN,
    SAMPLE_EBPF_EXT_CONTROL_RUN_BATCH,
    SAMPLE_EBPF_EXT_CONTROL_PROFILE,
} sample_ebpf_ext_control_code_t;

typedef enum _sample_ebpf_ext_flag
{
    SAMPLE_EBPF_EXT_FLAG_DISPATCH,
} sample_ebpf_ext_flag_t;

typedef struct _sample_ebpf_ext_profile_request
{
    uint64_t iterations;
    uint64_t flags;
    uint8_t data[1];
} sample_ebpf_ext_profile_request_t;

typedef struct _sample_ebpf_ext_profile_reply
{
    uint64_t duration;
} sample_ebpf_ext_profile_reply_t;

typedef struct _sample_ebpf_ext_batch_run_request
{
    uint32_t count;
    uint8_t data[1];
} sample_ebpf_ext_batch_run_request_t;

typedef struct _sample_ebpf_ext_batch_run_reply
{
    uint32_t status;
    uint8_t data[1];
} sample_ebpf_ext_batch_run_reply_t;

#define SAMPLE_EBPF_PROGRAM_BATCH_INVOCATION_COUNT 10

#define IOCTL_SAMPLE_EBPF_EXT_CTL_RUN \
    CTL_CODE(FILE_DEVICE_NETWORK, SAMPLE_EBPF_EXT_CONTROL_RUN, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SAMPLE_EBPF_EXT_CTL_RUN_BATCH \
    CTL_CODE(FILE_DEVICE_NETWORK, SAMPLE_EBPF_EXT_CONTROL_RUN_BATCH, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SAMPLE_EBPF_EXT_CTL_PROFILE \
    CTL_CODE(FILE_DEVICE_NETWORK, SAMPLE_EBPF_EXT_CONTROL_PROFILE, METHOD_BUFFERED, FILE_ANY_ACCESS)
