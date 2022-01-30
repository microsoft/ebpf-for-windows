// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <netsh.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include "ebpf_api.h"
#include "elf.h"
#include "links.h"
#include "maps.h"
#include "pins.h"
#include "programs.h"
#include "resource.h"

static const GUID g_EbpfHelperGuid = {/* 634d21b8-13f9-46a3-945f-885cbd661c13 */
                                      0x634d21b8,
                                      0x13f9,
                                      0x46a3,
                                      {0x94, 0x5f, 0x88, 0x5c, 0xbd, 0x66, 0x1c, 0x13}};

BOOL WINAPI
DllMain(HMODULE moduleHandle, DWORD reasonForCall, void* reserved)
{
    UNREFERENCED_PARAMETER(moduleHandle);
    UNREFERENCED_PARAMETER(reasonForCall);
    UNREFERENCED_PARAMETER(reserved);
    return TRUE;
}

// Verbs
#define CMD_GROUP_ADD L"add"
#define CMD_GROUP_DELETE L"delete"
#define CMD_GROUP_SET L"set"
#define CMD_GROUP_SHOW L"show"

// Nouns
#define CMD_EBPF_SHOW_DISASSEMBLY L"disassembly"
#define CMD_EBPF_SHOW_LINKS L"links"
#define CMD_EBPF_SHOW_MAPS L"maps"
#define CMD_EBPF_SHOW_PINS L"pins"

#define CMD_EBPF_ADD_PROGRAM L"program"
#define CMD_EBPF_DELETE_PROGRAM L"program"
#define CMD_EBPF_SET_PROGRAM L"program"
#define CMD_EBPF_SHOW_PROGRAMS L"programs"

#define CMD_EBPF_SHOW_SECTIONS L"sections"
#define CMD_EBPF_SHOW_VERIFICATION L"verification"

CMD_ENTRY g_EbpfAddCommandTable[] = {
    CREATE_CMD_ENTRY(EBPF_ADD_PROGRAM, handle_ebpf_add_program),
};
CMD_ENTRY g_EbpfDeleteCommandTable[] = {
    CREATE_CMD_ENTRY(EBPF_DELETE_PROGRAM, handle_ebpf_delete_program),
};
CMD_ENTRY g_EbpfSetCommandTable[] = {
    CREATE_CMD_ENTRY(EBPF_SET_PROGRAM, handle_ebpf_set_program),
};
CMD_ENTRY g_EbpfShowCommandTable[] = {
    CREATE_CMD_ENTRY(EBPF_SHOW_DISASSEMBLY, handle_ebpf_show_disassembly),
    CREATE_CMD_ENTRY(EBPF_SHOW_LINKS, handle_ebpf_show_links),
    CREATE_CMD_ENTRY(EBPF_SHOW_MAPS, handle_ebpf_show_maps),
    CREATE_CMD_ENTRY(EBPF_SHOW_PINS, handle_ebpf_show_pins),
    CREATE_CMD_ENTRY(EBPF_SHOW_PROGRAMS, handle_ebpf_show_programs),
    CREATE_CMD_ENTRY(EBPF_SHOW_SECTIONS, handle_ebpf_show_sections),
    CREATE_CMD_ENTRY(EBPF_SHOW_VERIFICATION, handle_ebpf_show_verification),
};

#define HLP_GROUP_ADD 1100
#define HLP_GROUP_ADD_EX 1101
#define HLP_GROUP_DELETE 1102
#define HLP_GROUP_DELETE_EX 1103
#define HLP_GROUP_SET 1104
#define HLP_GROUP_SET_EX 1105
#define HLP_GROUP_SHOW 1106
#define HLP_GROUP_SHOW_EX 1107

static CMD_GROUP_ENTRY g_EbpfGroupCommands[] = {
    CREATE_CMD_GROUP_ENTRY(GROUP_ADD, g_EbpfAddCommandTable),
    CREATE_CMD_GROUP_ENTRY(GROUP_DELETE, g_EbpfDeleteCommandTable),
    CREATE_CMD_GROUP_ENTRY(GROUP_SET, g_EbpfSetCommandTable),
    CREATE_CMD_GROUP_ENTRY(GROUP_SHOW, g_EbpfShowCommandTable),
};

DWORD WINAPI
EbpfStartHelper(const GUID* parentGuid, DWORD version)
{
    NS_CONTEXT_ATTRIBUTES attributes = {0};
    UNREFERENCED_PARAMETER(parentGuid);
    UNREFERENCED_PARAMETER(version);

    attributes.pwszContext = L"ebpf";
    attributes.guidHelper = g_EbpfHelperGuid;
    attributes.dwVersion = 1;
    attributes.dwFlags = CMD_FLAG_LOCAL | CMD_FLAG_ONLINE;
    attributes.ulNumGroups = _countof(g_EbpfGroupCommands);
    attributes.pCmdGroups = (CMD_GROUP_ENTRY(*)[]) & g_EbpfGroupCommands;

    DWORD status = RegisterContext(&attributes);

    return status;
}

__declspec(dllexport) DWORD InitHelperDll(DWORD netshVersion, void* reserved)
{
    NS_HELPER_ATTRIBUTES attributes = {0};
    UNREFERENCED_PARAMETER(netshVersion);
    UNREFERENCED_PARAMETER(reserved);
    attributes.guidHelper = g_EbpfHelperGuid;
    attributes.dwVersion = 1;
    attributes.pfnStart = EbpfStartHelper;

    DWORD status = RegisterHelper(NULL, &attributes);

    return status;
}
