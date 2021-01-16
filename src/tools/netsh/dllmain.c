// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "programs.h"

static const GUID g_EbpfHelperGuid = { /* 634d21b8-13f9-46a3-945f-885cbd661c13 */
    0x634d21b8,
    0x13f9,
    0x46a3,
    {0x94, 0x5f, 0x88, 0x5c, 0xbd, 0x66, 0x1c, 0x13}
};

BOOL WINAPI DllMain(
    HMODULE hModule,
    DWORD  ul_reason_for_call,
    void* reserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

#define HLP_EBPF_ADD_PROGRAM        1001
#define HLP_EBPF_ADD_PROGRAM_EX     1002
#define HLP_EBPF_DELETE_PROGRAM     1003
#define HLP_EBPF_DELETE_PROGRAM_EX  1004
#define HLP_EBPF_SET_PROGRAM        1007
#define HLP_EBPF_SET_PROGRAM_EX     1008
#define HLP_EBPF_SHOW_PROGRAMS       1013
#define HLP_EBPF_SHOW_PROGRAMS_EX    1014

#define CMD_EBPF_ADD_PROGRAM        L"program"
#define CMD_EBPF_DELETE_PROGRAM     L"program"
#define CMD_EBPF_SET_PROGRAM        L"program"
#define CMD_EBPF_SHOW_PROGRAMS      L"programs"

CMD_ENTRY g_EbpfAddCmdTable[] =
{
    CREATE_CMD_ENTRY(EBPF_ADD_PROGRAM, HandleEbpfAddProgram),
};
CMD_ENTRY g_EbpfDeleteCmdTable[] =
{
    CREATE_CMD_ENTRY(EBPF_DELETE_PROGRAM, HandleEbpfDeleteProgram),
};
CMD_ENTRY g_EbpfSetCmdTable[] =
{
    CREATE_CMD_ENTRY(EBPF_SET_PROGRAM, HandleEbpfSetProgram),
};
CMD_ENTRY g_EbpfShowCmdTable[] =
{
    CREATE_CMD_ENTRY(EBPF_SHOW_PROGRAMS, HandleEbpfShowPrograms),
};

#define HLP_GROUP_ADD        1100
#define HLP_GROUP_ADD_EX     1101
#define HLP_GROUP_DELETE     1102
#define HLP_GROUP_DELETE_EX  1103
#define HLP_GROUP_SET        1104
#define HLP_GROUP_SET_EX     1105
#define HLP_GROUP_SHOW       1106
#define HLP_GROUP_SHOW_EX    1107

#define CMD_GROUP_ADD        L"add"
#define CMD_GROUP_DELETE     L"delete"
#define CMD_GROUP_SET        L"set"
#define CMD_GROUP_SHOW       L"show"

static CMD_GROUP_ENTRY g_EbpfGroupCmds[] =
{
    CREATE_CMD_GROUP_ENTRY(GROUP_ADD,    g_EbpfAddCmdTable),
    CREATE_CMD_GROUP_ENTRY(GROUP_DELETE, g_EbpfDeleteCmdTable),
    CREATE_CMD_GROUP_ENTRY(GROUP_SET,    g_EbpfSetCmdTable),
    CREATE_CMD_GROUP_ENTRY(GROUP_SHOW,   g_EbpfShowCmdTable),
};

DWORD WINAPI EbpfStartHelper(const GUID* pguidParent, DWORD version)
{
    DWORD dwErr;
    NS_CONTEXT_ATTRIBUTES attMyAttributes = { 0 };

    attMyAttributes.pwszContext = L"ebpf";
    attMyAttributes.guidHelper = g_EbpfHelperGuid;
    attMyAttributes.dwVersion = 1;
    attMyAttributes.dwFlags = CMD_FLAG_LOCAL | CMD_FLAG_ONLINE;
    attMyAttributes.ulNumTopCmds = 0;
    attMyAttributes.pTopCmds = NULL;
    attMyAttributes.ulNumGroups = _countof(g_EbpfGroupCmds);
    attMyAttributes.pCmdGroups = (CMD_GROUP_ENTRY(*)[]) & g_EbpfGroupCmds;

    dwErr = RegisterContext(&attMyAttributes);

    return dwErr;
}

static const GUID g_NetshGuid = NETSH_ROOT_GUID;

__declspec(dllexport)
DWORD
InitHelperDll(DWORD netshVersion, void* reserved)
{
    NS_HELPER_ATTRIBUTES attMyAttributes = { 0 };

    attMyAttributes.guidHelper = g_EbpfHelperGuid;
    attMyAttributes.dwVersion = 1;
    attMyAttributes.pfnStart = EbpfStartHelper;

    DWORD err = RegisterHelper(&g_NetshGuid, &attMyAttributes);

    return NO_ERROR;
}
