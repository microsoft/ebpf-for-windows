// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

/**
 * @file
 * @brief Defines the entry point for the DLL application.
 */
#include "api_internal.h"

bool use_ebpf_store = true;

bool APIENTRY
DllMain(HMODULE hModule, unsigned long ul_reason_for_call, void* lpReserved)
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
        ebpf_api_thread_local_initialize();
        break;
    case DLL_THREAD_DETACH:
        ebpf_api_thread_local_cleanup();
        break;
    case DLL_PROCESS_DETACH:
        ebpf_api_terminate();
        break;
    }
    return TRUE;
}
