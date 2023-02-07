// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/**
 * @file
 * @brief Defines the entry point for the DLL application.
 */
#include "api_internal.h"
#include "framework.h"

bool use_ebpf_store = true;

BOOL APIENTRY
DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    UNREFERENCED_PARAMETER(hModule);
    UNREFERENCED_PARAMETER(lpReserved);
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        if (ebpf_api_initiate() != 0) {
            return FALSE;
        }
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        ebpf_api_terminate();
        break;
    }
    return TRUE;
}
