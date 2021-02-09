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

    DLL DWORD EbpfApiLoadProgram(const char* file, const char* section_name, HANDLE* handle, char** error_message);
    DLL void EbpfApiFreeErrorMessage(char* error_message);
    DLL void EbpfApiUnloadProgram(HANDLE handle);

    DLL DWORD EbpfApiAttachProgram(HANDLE handle, DWORD hook_point);
    DLL DWORD EbpfApiDetachProgram(HANDLE handle, DWORD hook_point);

#ifdef __cplusplus
}
#endif
