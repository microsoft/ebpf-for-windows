// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <windows.h>
#include <netsh.h> // Must be included after windows.h
#include <string.h>
#include "bpf/bpf.h"
#include "capture_helper.hpp"
#include "catch_wrapper.hpp"
#include "elf.h"
#include "links.h"
#include "maps.h"
#include "pins.h"
#include "programs.h"

#pragma region
// Mock Netsh.exe APIs.

// This function has incorrect SAL annotations, but it's declared in public headers so we can't fix it.
unsigned long WINAPI
PreprocessCommand(
    _In_opt_ HANDLE hModule,
    _Inout_updates_(dwArgCount) wchar_t** ppwcArguments,
    _In_ unsigned long dwCurrentIndex,
    _In_ unsigned long dwArgCount,
    _Inout_updates_opt_(dwTagCount) TAG_TYPE* pttTags,
    _In_ unsigned long dwTagCount,
    _In_ unsigned long dwMinArgs,
    _In_ unsigned long dwMaxArgs,
    _Out_writes_opt_(dwArgCount - dwCurrentIndex) unsigned long* pdwTagType);

unsigned long
MatchEnumTag(
    HANDLE hModule,
    const wchar_t* pwcArg,
    unsigned long dwNumArg,
    const TOKEN_VALUE* pEnumTable,
    unsigned long* pdwValue);
#pragma endregion

std::string
_run_netsh_command(
    _In_ FN_HANDLE_CMD* command,
    _In_opt_z_ const wchar_t* arg1,
    _In_opt_z_ const wchar_t* arg2,
    _In_opt_z_ const wchar_t* arg3,
    _Out_ int* result);

std::string
run_netsh_command_with_args(_In_ FN_HANDLE_CMD* command, _Out_ int* result, int argc, ...);
