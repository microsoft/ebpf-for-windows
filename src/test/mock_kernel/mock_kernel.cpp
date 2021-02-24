/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
*/

#include "pch.h"
#include "framework.h"
#include <stdlib.h>
#include <vector>
#include <map>

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
    PKSPIN_LOCK SpinLock)
{
    return 0;
}

MOCKKERNEL_API 
VOID KeReleaseSpinLock(
    PKSPIN_LOCK SpinLock,
    UCHAR NewIrql
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


MOCKKERNEL_API
void ExFreePoolWithTag(
    PVOID P,
    ULONG tag
)
{
    free(P);
}

typedef enum class _RTL_GENERIC_COMPARE_RESULTS {
    GenericLessThan,
    GenericGreaterThan,
    GenericEqual
} RTL_GENERIC_COMPARE_RESULTS;


typedef RTL_GENERIC_COMPARE_RESULTS
(*PRTL_AVL_COMPARE_ROUTINE) (
    void* table,
    void* first_struct,
    void* second_struct
    );

typedef struct _RTL_AVL_TABLE {
    std::vector<std::vector<uint8_t>>* entries;
    void* padding[2];
    uint8_t padding2[4];
    PVOID OrderedPointer;
    ULONG WhichOrderedElement;
    ULONG NumberGenericTableElements;
    ULONG DepthOfTree;
    void* RestartKey;
    ULONG DeleteCount;
    PRTL_AVL_COMPARE_ROUTINE CompareRoutine;
    void* AllocateRoutine;
    void* FreeRoutine;
    PVOID TableContext;
} RTL_AVL_TABLE;
typedef RTL_AVL_TABLE* PRTL_AVL_TABLE;


MOCKKERNEL_API
void RtlInitializeGenericTableAvl(
    PRTL_AVL_TABLE table,
    PRTL_AVL_COMPARE_ROUTINE compare_routine,
    PVOID allocate_routine,
    PVOID free_routine,
    PVOID table_context)
{
    table->CompareRoutine = compare_routine;
    table->TableContext = table_context;
    table->entries = new std::vector<std::vector<uint8_t>>();
}

size_t find_entry(PRTL_AVL_TABLE table, uint8_t* key)
{
    auto entries = table->entries;
    for (size_t i = 0; i < entries->size(); i ++)
    {
        if (entries->at(i).size() == 0)
        {
            continue;
        }

        if (table->CompareRoutine(table, key, entries->at(i).data()) == RTL_GENERIC_COMPARE_RESULTS::GenericEqual)
        {
            return i;
        }
    }
    return -1;
}

MOCKKERNEL_API
PVOID RtlInsertElementGenericTableAvl(
    PRTL_AVL_TABLE table,
    uint8_t*       buffer,
    const uint32_t buffer_size,
    PBOOLEAN       new_element)
{
    auto entries = table->entries;
    size_t index = find_entry(table, buffer);
    if (index != -1)
    {
        *new_element = FALSE;
        return entries->at(index).data();
    }

    std::vector<uint8_t> new_entry(buffer_size);
    std::copy(buffer, buffer + buffer_size, new_entry.begin());
    entries->push_back(new_entry);
    return entries->back().data();
}

MOCKKERNEL_API
BOOLEAN RtlDeleteElementGenericTableAvl(
    PRTL_AVL_TABLE       table,
    uint8_t*    buffer)
{
    auto entries = table->entries;
    size_t index = find_entry(table, buffer);
    if (index != -1)
    {
        entries->at(index).resize(0);
        return TRUE;
    }
    return FALSE;
}

MOCKKERNEL_API
PVOID RtlLookupElementGenericTableAvl(
    PRTL_AVL_TABLE       table,
    uint8_t* buffer)
{
    auto entries = table->entries;
    size_t index = find_entry(table, buffer);
    if (index != -1)
    {
        return entries->at(index).data();
    }
    return NULL;
}

}