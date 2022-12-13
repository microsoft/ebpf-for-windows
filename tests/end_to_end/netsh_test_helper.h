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

DWORD WINAPI
PreprocessCommand(
    _In_opt_ const HANDLE hModule,
    _Inout_updates_(dwArgCount) LPWSTR* ppwcArguments,
    _In_ const DWORD dwCurrentIndex,
    _In_ const DWORD dwArgCount,
    _Inout_updates_opt_(dwTagCount) TAG_TYPE* pttTags,
    _In_ const DWORD dwTagCount,
    _In_ const DWORD dwMinArgs,
    _In_ const DWORD dwMaxArgs,
    _Out_writes_opt_(dwArgCount - dwCurrentIndex) DWORD* pdwTagType);

DWORD
MatchEnumTag(HANDLE hModule, LPCWSTR pwcArg, DWORD dwNumArg, const TOKEN_VALUE* pEnumTable, PDWORD pdwValue);
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
