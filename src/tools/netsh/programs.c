// Copyright (C) Microsoft.
// SPDX-License-Identifier: MIT
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <netsh.h>
#include "programs.h"

unsigned long HandleEbpfAddProgram(
    LPCWSTR machine,
    LPWSTR* argv,
    DWORD currentIndex,
    DWORD argc,
    DWORD flags,
    LPCVOID data,
    BOOL* done)
{
    return ERROR_CALL_NOT_IMPLEMENTED;
}

DWORD HandleEbpfDeleteProgram(
    LPCWSTR machine,
    LPWSTR* argv,
    DWORD currentIndex,
    DWORD argc,
    DWORD flags,
    LPCVOID data,
    BOOL* done)
{
    return ERROR_CALL_NOT_IMPLEMENTED;
}

DWORD HandleEbpfSetProgram(
    LPCWSTR machine,
    LPWSTR* argv,
    DWORD currentIndex,
    DWORD argc,
    DWORD flags,
    LPCVOID data,
    BOOL* done)
{
    return ERROR_CALL_NOT_IMPLEMENTED;
}

DWORD HandleEbpfShowPrograms(
    LPCWSTR machine,
    LPWSTR* argv,
    DWORD currentIndex,
    DWORD argc,
    DWORD flags,
    LPCVOID data,
    BOOL* done)
{
    return ERROR_CALL_NOT_IMPLEMENTED;
}