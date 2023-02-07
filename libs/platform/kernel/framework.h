// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#include <ntdef.h>
#include <ntstatus.h>
#pragma warning(push)
#pragma warning(disable : 28253) // Inconsistent annotation for '_umul128'
#include <ntintsafe.h>
#pragma warning(pop)
#include <ntifs.h>
#include <netioddk.h>
#include <ntddk.h>
#include <stdint.h>
#include <wdm.h>

#define bool BOOLEAN
#define true 1
#define false 0

#ifdef _DEBUG
#define ebpf_assert(x) ASSERT(x)
#else
#define ebpf_assert(x) (void)(x)
#endif // !_DEBUG

#define ebpf_list_entry_t LIST_ENTRY

#define ebpf_list_initialize InitializeListHead
#define ebpf_list_is_empty IsListEmpty
#define ebpf_list_insert_tail InsertTailList
#define ebpf_list_remove_entry RemoveEntryList
#define ebpf_list_remove_head_entry RemoveHeadList
#define ebpf_list_append_tail_list AppendTailList
#define ebpf_probe_for_write ProbeForWrite
