// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#include <ntdef.h>
#include <ntstatus.h>
#include <ntintsafe.h>
#include <ntddk.h>
#define uint8_t UINT8
#define uint16_t UINT16
#define uint32_t UINT32
#define uint64_t UINT64

#define int8_t INT8
#define int16_t INT16
#define int32_t INT32
#define int64_t INT64

#define bool BOOLEAN
#define true 1
#define false 0

#define ebpf_assert(x) ASSERT(x)

#define ebpf_list_entry_t LIST_ENTRY

#define ebpf_list_initialize InitializeListHead
#define ebpf_list_is_empty IsListEmpty
#define ebpf_list_insert_tail InsertTailList
#define ebpf_list_remove_entry RemoveEntryList