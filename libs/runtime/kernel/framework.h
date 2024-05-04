// Copyright (c) eBPF for Windows contributors
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
#pragma warning(push)
#pragma warning(disable : 28196) // Inconsistent annotation for '_umul128'
#include <ntstrsafe.h>
#pragma warning(pop)
#include <stdbool.h>
#include <stdint.h>
#include <wdm.h>

#define ebpf_list_entry_t LIST_ENTRY

#define ebpf_list_initialize InitializeListHead
#define ebpf_list_is_empty IsListEmpty
#define ebpf_list_insert_tail InsertTailList
#define ebpf_list_remove_entry RemoveEntryList
#define ebpf_list_remove_head_entry RemoveHeadList
#define ebpf_list_append_tail_list AppendTailList
#define ebpf_probe_for_write ProbeForWrite
#define ebpf_fault_injection_is_enabled() false
