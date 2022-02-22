// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
// Windows Header Files
#include <windows.h>

#include <cstdint>
#include <iostream>
#include <string>

#include "bpf2c.h"

extern "C" metadata_table_t bindmonitor_metadata_table;
extern "C" metadata_table_t divide_by_zero_metadata_table;
extern "C" metadata_table_t droppacket_metadata_table;

BOOL APIENTRY
DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    UNREFERENCED_PARAMETER(hModule);
    UNREFERENCED_PARAMETER(lpReserved);
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

void
division_by_zero(uint32_t address)
{
    std::cerr << "Divide by zero at address" << address << std::endl;
}

#define FIND_METADATA_ENTRTY(NAME, X) \
    if (std::string(NAME) == #X)      \
        return &X##_metadata_table;

extern "C" metadata_table_t*
get_metadata_table(const char* name)
{
    FIND_METADATA_ENTRTY(name, bindmonitor);
    FIND_METADATA_ENTRTY(name, divide_by_zero);
    FIND_METADATA_ENTRTY(name, droppacket);
    return nullptr;
}