// Copyright (C) Microsoft.
// SPDX-License-Identifier: MIT
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdlib.h>
#include <netsh.h>
#include "elf.h"
#include "programs.h"
#include "resource.h"
#include "api.h"

static const GUID g_EbpfHelperGuid = { /* 634d21b8-13f9-46a3-945f-885cbd661c13 */
    0x634d21b8,
    0x13f9,
    0x46a3,
    {0x94, 0x5f, 0x88, 0x5c, 0xbd, 0x66, 0x1c, 0x13}
};

BOOL WINAPI DllMain(
    HMODULE moduleHandle,
    DWORD  reasonForCall,
    void* reserved)
{
    return TRUE;
}

// Verbs
#define CMD_GROUP_ADD        L"add"
#define CMD_GROUP_DELETE     L"delete"
#define CMD_GROUP_SET        L"set"
#define CMD_GROUP_SHOW       L"show"

// Nouns
#define CMD_EBPF_ADD_PROGRAM        L"program"
#define CMD_EBPF_DELETE_PROGRAM     L"program"
#define CMD_EBPF_SET_PROGRAM        L"program"
#define CMD_EBPF_SHOW_PROGRAMS      L"programs"
#define CMD_EBPF_SHOW_SECTIONS      L"sections"
#define CMD_EBPF_SHOW_DISASSEMBLY   L"disassembly"
#define CMD_EBPF_SHOW_VERIFICATION  L"verification"

CMD_ENTRY g_EbpfAddCommandTable[] =
{
    CREATE_CMD_ENTRY(EBPF_ADD_PROGRAM, HandleEbpfAddProgram),
};
CMD_ENTRY g_EbpfDeleteCommandTable[] =
{
    CREATE_CMD_ENTRY(EBPF_DELETE_PROGRAM, HandleEbpfDeleteProgram),
};
CMD_ENTRY g_EbpfSetCommandTable[] =
{
    CREATE_CMD_ENTRY(EBPF_SET_PROGRAM, HandleEbpfSetProgram),
};
CMD_ENTRY g_EbpfShowCommandTable[] =
{
    CREATE_CMD_ENTRY(EBPF_SHOW_DISASSEMBLY, HandleEbpfShowDisassembly),
    CREATE_CMD_ENTRY(EBPF_SHOW_PROGRAMS, HandleEbpfShowPrograms),
    CREATE_CMD_ENTRY(EBPF_SHOW_SECTIONS, HandleEbpfShowSections),
    CREATE_CMD_ENTRY(EBPF_SHOW_VERIFICATION, HandleEbpfShowVerification),
};

#define HLP_GROUP_ADD        1100
#define HLP_GROUP_ADD_EX     1101
#define HLP_GROUP_DELETE     1102
#define HLP_GROUP_DELETE_EX  1103
#define HLP_GROUP_SET        1104
#define HLP_GROUP_SET_EX     1105
#define HLP_GROUP_SHOW       1106
#define HLP_GROUP_SHOW_EX    1107

static CMD_GROUP_ENTRY g_EbpfGroupCommands[] =
{
    CREATE_CMD_GROUP_ENTRY(GROUP_ADD,    g_EbpfAddCommandTable),
    CREATE_CMD_GROUP_ENTRY(GROUP_DELETE, g_EbpfDeleteCommandTable),
    CREATE_CMD_GROUP_ENTRY(GROUP_SET,    g_EbpfSetCommandTable),
    CREATE_CMD_GROUP_ENTRY(GROUP_SHOW,   g_EbpfShowCommandTable),
};

DWORD WINAPI EbpfStartHelper(const GUID* parentGuid, DWORD version)
{
    NS_CONTEXT_ATTRIBUTES attributes = { 0 };

    attributes.pwszContext = L"ebpf";
    attributes.guidHelper = g_EbpfHelperGuid;
    attributes.dwVersion = 1;
    attributes.dwFlags = CMD_FLAG_LOCAL | CMD_FLAG_ONLINE;
    attributes.ulNumGroups = _countof(g_EbpfGroupCommands);
    attributes.pCmdGroups = (CMD_GROUP_ENTRY(*)[]) & g_EbpfGroupCommands;

    DWORD status = RegisterContext(&attributes);

    return status;
}

__declspec(dllexport)
DWORD
InitHelperDll(DWORD netshVersion, void* reserved)
{
    NS_HELPER_ATTRIBUTES attributes = { 0 };

    attributes.guidHelper = g_EbpfHelperGuid;
    attributes.dwVersion = 1;
    attributes.pfnStart = EbpfStartHelper;

    DWORD status = RegisterHelper(NULL, &attributes);

    if (status == ERROR_SUCCESS)
    {
        status = EbpfApiInit();
    }

    return status;
}
