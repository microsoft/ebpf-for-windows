// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_shared_framework.h"

ebpf_result_t
ebpf_result_from_cxplat_status(cxplat_status_t status)
{
    switch (status) {
    case CXPLAT_STATUS_SUCCESS:
        return EBPF_SUCCESS;
    case CXPLAT_STATUS_NO_MEMORY:
        return EBPF_NO_MEMORY;
    case CXPLAT_STATUS_ARITHMETIC_OVERFLOW:
        return EBPF_ARITHMETIC_OVERFLOW;
    default:
        return EBPF_FAILED;
    }
}
