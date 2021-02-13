/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
*/

#include "pch.h"
#include "framework.h"
#include <stdlib.h>

#define MOCKKERNEL_API __declspec(dllexport)

extern "C"
{
MOCKKERNEL_API 
ULONG DbgPrintEx(
        ULONG ComponentId,
        ULONG Level,
        PCSTR Format,
        ...)
{
    return 0;
}

MOCKKERNEL_API 
void KeInitializeSpinLock(
    PKSPIN_LOCK SpinLock)
{
    *SpinLock = 0;
}

MOCKKERNEL_API
UCHAR KeAcquireSpinLockRaiseToDpc(
    _Inout_ PKSPIN_LOCK SpinLock)
{
    return 0;
}

MOCKKERNEL_API 
VOID KeReleaseSpinLock(
    _Inout_ PKSPIN_LOCK SpinLock,
    _In_ _IRQL_restores_ UCHAR NewIrql
)
{
}

MOCKKERNEL_API
DECLSPEC_RESTRICT
PVOID ExAllocatePool2(
    ULONG64 Flags,
    SIZE_T     NumberOfBytes,
    ULONG      Tag
    )
{
    return malloc(NumberOfBytes);
}

MOCKKERNEL_API
void ExFreePool(
    PVOID P
)
{
    free(P);
}

}