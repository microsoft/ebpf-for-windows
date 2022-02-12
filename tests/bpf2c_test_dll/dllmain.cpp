// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <cstdint>
#include <iostream>
#include <string>

#include "bpf2c.h"

extern "C" meta_data_table_t bindmonitor;
extern "C" meta_data_table_t divide_by_zero;
extern "C" meta_data_table_t droppacket;

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
    std::cerr << "Divide by zero at addres " << address << std::endl;
}

#define FIND_META_DATA_ENTRTY(NAME, X) \
    if (std::string(NAME) == #X)       \
        return &X;

extern "C" meta_data_table_t*
get_meta_data_table(const char* name)
{
    FIND_META_DATA_ENTRTY(name, bindmonitor);
    FIND_META_DATA_ENTRTY(name, divide_by_zero);
    FIND_META_DATA_ENTRTY(name, droppacket);
    return nullptr;
}