/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
// Windows Header Files
#include <windows.h>
#include <winioctl.h>

#if !defined(UNREFERENCED_PARAMETER)
#define UNREFERENCED_PARAMETER(X) (X)
#endif

// Types and functions from the ntddk duplicated here to allow user and kernel more closely allign.

//
//  The results of a compare can be less than, equal, or greater than.
//

typedef enum _RTL_GENERIC_COMPARE_RESULTS
{
    GenericLessThan,
    GenericGreaterThan,
    GenericEqual
} RTL_GENERIC_COMPARE_RESULTS;

struct _RTL_AVL_TABLE;

//
//  The comparison function takes as input pointers to elements containing
//  user defined structures and returns the results of comparing the two
//  elements.
//

typedef _IRQL_requires_same_ _Function_class_(RTL_AVL_COMPARE_ROUTINE) RTL_GENERIC_COMPARE_RESULTS NTAPI
    RTL_AVL_COMPARE_ROUTINE(_In_ struct _RTL_AVL_TABLE* Table, _In_ PVOID FirstStruct, _In_ PVOID SecondStruct);
typedef RTL_AVL_COMPARE_ROUTINE* PRTL_AVL_COMPARE_ROUTINE;

//
//  The allocation function is called by the generic table package whenever
//  it needs to allocate memory for the table.
//

typedef _IRQL_requires_same_ _Function_class_(RTL_AVL_ALLOCATE_ROUTINE) __drv_allocatesMem(Mem) PVOID NTAPI
    RTL_AVL_ALLOCATE_ROUTINE(_In_ struct _RTL_AVL_TABLE* Table, _In_ const uint32_t ByteSize);
typedef RTL_AVL_ALLOCATE_ROUTINE* PRTL_AVL_ALLOCATE_ROUTINE;

//
//  The deallocation function is called by the generic table package whenever
//  it needs to deallocate memory from the table that was allocated by calling
//  the user supplied allocation function.
//

typedef _IRQL_requires_same_ _Function_class_(RTL_AVL_FREE_ROUTINE) VOID NTAPI
    RTL_AVL_FREE_ROUTINE(_In_ struct _RTL_AVL_TABLE* Table, _In_ __drv_freesMem(Mem) _Post_invalid_ PVOID Buffer);
typedef RTL_AVL_FREE_ROUTINE* PRTL_AVL_FREE_ROUTINE;

typedef struct _RTL_BALANCED_LINKS
{
    struct _RTL_BALANCED_LINKS* Parent;
    struct _RTL_BALANCED_LINKS* LeftChild;
    struct _RTL_BALANCED_LINKS* RightChild;
    CHAR Balance;
    UCHAR Reserved[3];
} RTL_BALANCED_LINKS;
typedef RTL_BALANCED_LINKS* PRTL_BALANCED_LINKS;

typedef struct _RTL_AVL_TABLE
{
    RTL_BALANCED_LINKS BalancedRoot;
    PVOID OrderedPointer;
    ULONG WhichOrderedElement;
    ULONG NumberGenericTableElements;
    ULONG DepthOfTree;
    PRTL_BALANCED_LINKS RestartKey;
    ULONG DeleteCount;
    PRTL_AVL_COMPARE_ROUTINE CompareRoutine;
    PRTL_AVL_ALLOCATE_ROUTINE AllocateRoutine;
    PRTL_AVL_FREE_ROUTINE FreeRoutine;
    PVOID TableContext;
} RTL_AVL_TABLE;
typedef RTL_AVL_TABLE* PRTL_AVL_TABLE;

#ifdef __cplusplus
extern "C"
{
#endif

    extern void (*RtlInitializeGenericTableAvl)(
        _Out_ PRTL_AVL_TABLE Table,
        _In_ PRTL_AVL_COMPARE_ROUTINE CompareRoutine,
        _In_ PRTL_AVL_ALLOCATE_ROUTINE AllocateRoutine,
        _In_ PRTL_AVL_FREE_ROUTINE FreeRoutine,
        _In_opt_ PVOID TableContext);

    extern void* (*RtlEnumerateGenericTableAvl)(_In_ PRTL_AVL_TABLE Table, _In_ BOOLEAN Restart);

    extern BOOLEAN (*RtlDeleteElementGenericTableAvl)(_In_ PRTL_AVL_TABLE Table, _In_ PVOID Buffer);

    extern void* (*RtlLookupElementGenericTableAvl)(_In_ PRTL_AVL_TABLE Table, _In_ PVOID Buffer);

    extern void* (*RtlInsertElementGenericTableAvl)(
        _In_ PRTL_AVL_TABLE Table,
        _In_reads_bytes_(BufferSize) PVOID Buffer,
        _In_ const uint32_t BufferSize,
        _Out_opt_ PBOOLEAN NewElement);

    extern PVOID (*RtlLookupFirstMatchingElementGenericTableAvl)(
        _In_ PRTL_AVL_TABLE Table, _In_ PVOID Buffer, _Out_ PVOID* RestartKey);
#ifdef __cplusplus
}
#endif