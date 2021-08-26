// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
// Windows Header Files
#include <rpc.h>
#include <windows.h>
#include <winioctl.h>

#pragma comment(lib, "rpcrt4")

#define ebpf_assert(x) assert(x)

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
    ebpf_list_remove_entry(_In_ ebpf_list_entry_t* entry)
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

#ifdef __cplusplus
}
#endif