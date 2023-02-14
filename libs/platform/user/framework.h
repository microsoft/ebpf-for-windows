// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
// Windows Header Files
#include <windows.h>
#include <rpc.h>
#include <winioctl.h>
typedef _Return_type_success_(return >= 0) long NTSTATUS;
#include <../km/netioddk.h>
#include <kernel_um.h>
#include <netiodef.h>
#define STATUS_NOINTERFACE ((NTSTATUS)0xC00002B9L)

#pragma comment(lib, "rpcrt4")

#ifdef _DEBUG
#define ebpf_assert(x) assert(x)
#else
#define ebpf_assert(x) (void)(x)
#endif //!_DEBUG

#if !defined(UNREFERENCED_PARAMETER)
#define UNREFERENCED_PARAMETER(X) (X)
#endif

// Types and functions from the ntddk duplicated here to allow user and kernel more closely align.

#ifdef __cplusplus
extern "C"
{
#endif
    typedef LIST_ENTRY ebpf_list_entry_t;

    inline void
    ebpf_list_initialize(_Out_ ebpf_list_entry_t* list_head)
    {

        list_head->Flink = list_head->Blink = list_head;
        return;
    }

    inline bool
    ebpf_list_is_empty(_In_ const ebpf_list_entry_t* list_head)
    {

        return (list_head->Flink == list_head);
    }

    inline void
    ebpf_list_insert_tail(_Inout_ ebpf_list_entry_t* list_head, _Out_ ebpf_list_entry_t* entry)
    {
        ebpf_list_entry_t* previous_entry;
        previous_entry = list_head->Blink;

        entry->Flink = list_head;
        entry->Blink = previous_entry;
        previous_entry->Flink = entry;
        list_head->Blink = entry;
        ebpf_assert(list_head->Blink->Flink == list_head);
        ebpf_assert(list_head->Flink->Blink == list_head);
        return;
    }

    inline bool
    ebpf_list_remove_entry(_Inout_ ebpf_list_entry_t* entry)
    {
        ebpf_list_entry_t* previous_entry;
        ebpf_list_entry_t* next_entry;

        next_entry = entry->Flink;
        previous_entry = entry->Blink;

        previous_entry->Flink = next_entry;
        next_entry->Blink = previous_entry;
        return (previous_entry == next_entry);
    }

    inline ebpf_list_entry_t*
    ebpf_list_remove_head_entry(_Inout_ ebpf_list_entry_t* list_head)
    {
        if (list_head->Flink == list_head) {
            return list_head;
        }
        ebpf_list_entry_t* removed = list_head->Flink;
        list_head->Flink = removed->Flink;
        removed->Flink->Blink = list_head;

        return removed;
    }

    inline void
    ebpf_list_append_tail_list(_Inout_ ebpf_list_entry_t* list_head, _Inout_ ebpf_list_entry_t* list_to_append)
    {
        ebpf_list_entry_t* list_end = list_head->Blink;

        list_head->Blink->Flink = list_to_append;
        list_head->Blink = list_to_append->Blink;
        list_to_append->Blink->Flink = list_head;
        list_to_append->Blink = list_end;
    }

    inline void
    ebpf_probe_for_write(_Out_writes_bytes_(length) void* address, size_t length, unsigned long alignment)
    {
        if (((uintptr_t)address % alignment) != 0) {
            RaiseException(STATUS_DATATYPE_MISALIGNMENT, 0, 0, NULL);
        }
        UNREFERENCED_PARAMETER(length);
    }

#ifdef __cplusplus
}
#endif
