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
extern "C" metadata_table_t bindmonitor_tailcall_metadata_table;
extern "C" metadata_table_t bindmonitor_ringbuf_metadata_table;
extern "C" metadata_table_t map_metadata_table;
extern "C" metadata_table_t cgroup_sock_addr_metadata_table;
extern "C" metadata_table_t test_utility_helpers_metadata_table;
extern "C" metadata_table_t map_reuse_metadata_table;
extern "C" metadata_table_t map_reuse_2_metadata_table;
extern "C" metadata_table_t map_in_map_metadata_table;
extern "C" metadata_table_t map_in_map_v2_metadata_table;
extern "C" metadata_table_t tail_call_metadata_table;
extern "C" metadata_table_t tail_call_bad_metadata_table;
extern "C" metadata_table_t tail_call_multiple_metadata_table;

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

#define FIND_METADATA_ENTRY(NAME, X) \
    if (std::string(NAME) == #X)     \
        return &X##_metadata_table;

extern "C" metadata_table_t*
get_metadata_table(const char* name)
{
    FIND_METADATA_ENTRY(name, bindmonitor);
    FIND_METADATA_ENTRY(name, divide_by_zero);
    FIND_METADATA_ENTRY(name, droppacket);
    FIND_METADATA_ENTRY(name, bindmonitor_tailcall);
    FIND_METADATA_ENTRY(name, bindmonitor_ringbuf);
    FIND_METADATA_ENTRY(name, map);
    FIND_METADATA_ENTRY(name, cgroup_sock_addr);
    FIND_METADATA_ENTRY(name, test_utility_helpers);
    FIND_METADATA_ENTRY(name, map_reuse);
    FIND_METADATA_ENTRY(name, map_reuse_2);
    FIND_METADATA_ENTRY(name, map_in_map);
    FIND_METADATA_ENTRY(name, map_in_map_v2);
    FIND_METADATA_ENTRY(name, tail_call);
    FIND_METADATA_ENTRY(name, tail_call_bad);
    FIND_METADATA_ENTRY(name, tail_call_multiple);
    return nullptr;
}