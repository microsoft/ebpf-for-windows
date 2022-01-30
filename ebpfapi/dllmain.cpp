// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "api_internal.h"

BOOL APIENTRY
DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    UNREFERENCED_PARAMETER(hModule);
    UNREFERENCED_PARAMETER(lpReserved);
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        printf("DllMain: Calling ebpf_api_initiate\n");
        if (ebpf_api_initiate() != 0) {
            printf("DllMain: ebpf_api_initiate failed\n");
            return FALSE;
        }
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        printf("DllMain: Calling ebpf_api_terminate\n");
        ebpf_api_terminate();
        break;
    }
    return TRUE;
}
