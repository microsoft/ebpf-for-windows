/*
 *  Copyright (C) 2020, Microsoft Corporation, All Rights Reserved
 *  SPDX-License-Identifier: MIT
*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#if defined(EBPF_API)
#define DLL __declspec(dllexport)
#else
#define DLL __declspec(dllimport)
#endif

#define EBPF_HOOK_POINT_XDP 1

    DLL DWORD EbpfApiInit();

    DLL void EbpfApiTerminate();

    DLL DWORD EbpfLoadProgram(const char* file, const char* section_name, HANDLE* handle, char** error_message);
    DLL void EbpfFreeErrorMessage(char* error_message);
    DLL void EbpfUnloadProgram(HANDLE handle);

    DLL DWORD EbpfAttachProgram(HANDLE handle, DWORD hook_point);
    DLL DWORD EbpfDetachProgram(HANDLE handle, DWORD hook_point);

#ifdef __cplusplus
}
#endif
