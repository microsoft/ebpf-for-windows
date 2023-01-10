// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#include "ebpf_platform.h"

void
ebpf_rundown_protection_initialize(_Out_ ebpf_rundown_protection_t* rundown_protection)
{
    ExInitializeRundownProtection((EX_RUNDOWN_REF*)rundown_protection);
}

void
ebpf_rundown_protection_wait(_Inout_ ebpf_rundown_protection_t* rundown_protection)
{
    ExWaitForRundownProtectionRelease((EX_RUNDOWN_REF*)rundown_protection);
}

bool
ebpf_rundown_protection_acquire(_Inout_ ebpf_rundown_protection_t* rundown_protection)
{
    return ExAcquireRundownProtection((EX_RUNDOWN_REF*)rundown_protection);
}

void
ebpf_rundown_protection_release(_Inout_ ebpf_rundown_protection_t* rundown_protection)
{
    ExReleaseRundownProtection((EX_RUNDOWN_REF*)rundown_protection);
}
